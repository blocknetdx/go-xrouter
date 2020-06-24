// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package xrouter

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/blocknetdx/go-xrouter/sn"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// These constants define the application version and follow the semantic
// versioning 2.0.0 spec (http://semver.org/).
const (
	appMajor uint = 4
	appMinor uint = 2
	appPatch uint = 1

	// appPreRelease MUST only contain characters from semanticAlphabet
	// per the semantic versioning spec.
	appPreRelease = "beta"

	// semanticAlphabet
	semanticAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
)

// xrouter namespaces
const (
	xr string = "xr::"
	xrs string = "xrs::"
)

// normalizeVerString returns the passed string stripped of all characters which
// are not valid according to the semantic versioning guidelines for pre-release
// version and build metadata strings.  In particular they MUST only contain
// characters in semanticAlphabet.
func normalizeVerString(str string) string {
	var result bytes.Buffer
	for _, r := range str {
		if strings.ContainsRune(semanticAlphabet, r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// version returns the application version as a properly formed string per the
// semantic versioning 2.0.0 spec (http://semver.org/).
func version() string {
	// Start with the major, minor, and patch versions.
	version := fmt.Sprintf("%d.%d.%d", appMajor, appMinor, appPatch)

	// Append pre-release version if there is one.  The hyphen called for
	// by the semantic versioning spec is automatically appended and should
	// not be contained in the pre-release string.  The pre-release version
	// is not appended if it contains invalid characters.
	preRelease := normalizeVerString(appPreRelease)
	if preRelease != "" {
		version = fmt.Sprintf("%s-%s", version, preRelease)
	}

	return version
}

type SnodeReply struct {
	Pubkey []byte
	Hash []byte
	Reply []byte
}

type Config struct {
	MaxPeers int
	SimNet bool
	DisableBanning bool
	BanThreshold uint32
	BanDuration time.Duration
	DataDir string
	AddPeers []string
	ConnectPeers []string
	whitelists []*net.IPNet
}

var cfg = Config{
	125,
	false,
	false,
	100,
	time.Hour * 24,
	".",
	[]string{},
	[]string{},
	[]*net.IPNet{},
}

type Client struct {
	params         *chaincfg.Params
	servicenodes   []*sn.ServiceNode
	services       map[string][]*sn.ServiceNode
	mu             sync.Mutex
	wg             sync.WaitGroup
	addrManager    *addrmgr.AddrManager
	connManager    *connmgr.ConnManager
	newPeers       chan *serverPeer
	donePeers      chan *serverPeer
	banPeers       chan *serverPeer
	broadcast      chan broadcastMsg
	quit           chan struct{}
	ready          chan bool
	query          chan interface{}
	interrupt      <-chan struct{}
	knownAddresses map[string]struct{}
	started        int32
	shutdown       int32
	shutdownSched  int32 // list of blacklisted substrings by which to filter user agents
	agentBlacklist []string // list of whitelisted user agent substrings, no whitelisting will be applied if the list is empty or nil
	agentWhitelist []string
	startupTime    int64
	bytesReceived  uint64 // Total bytes received from all peers since start
	bytesSent      uint64 // Total bytes sent by all peers since start
}

func NewClient(params chaincfg.Params) (*Client, error) {
	s := Client{}
	s.params = &params
	s.services = make(map[string][]*sn.ServiceNode)
	s.mu = sync.Mutex{}
	s.addrManager = addrmgr.New(cfg.DataDir, btcdLookup)
	s.newPeers = make(chan *serverPeer, cfg.MaxPeers)
	s.donePeers = make(chan *serverPeer, cfg.MaxPeers)
	s.banPeers = make(chan *serverPeer, cfg.MaxPeers)
	s.broadcast = make(chan broadcastMsg, cfg.MaxPeers)
	s.quit = make(chan struct{})
	s.ready = make(chan bool)
	s.query = make(chan interface{})
	s.interrupt = interruptListener()
	newAddressFunc := func() (net.Addr, error) {
		for tries := 0; tries < 100; tries++ {
			addr := s.addrManager.GetAddress()
			if addr == nil {
				break
			}

			// Address will not be invalid, local or unroutable
			// because addrmanager rejects those on addition.
			// Just check that we don't already have an address
			// in the same group so that we are not connecting
			// to the same network segment at the expense of
			// others.
			key := addrmgr.GroupKey(addr.NetAddress())
			if s.OutboundGroupCount(key) != 0 {
				continue
			}

			// Mark an attempt for the valid address.
			s.addrManager.Attempt(addr.NetAddress())
			addrString := addrmgr.NetAddressKey(addr.NetAddress())
			if s.connManager.HasConnection(addrString) {
				continue
			}

			netAddr, err := addrStringToNetAddr(addrString)
			if err != nil {
				continue
			}

			return netAddr, nil
		}

		return nil, errors.New("no valid connect address")
	}
	cmgr, err := connmgr.New(&connmgr.Config{
		Listeners:      nil,
		OnAccept:       nil,
		RetryDuration:  connectionRetryInterval,
		TargetOutbound: uint32(defaultTargetOutbound),
		Dial:           btcdDial,
		OnConnection:   s.outboundPeerConnected,
		GetNewAddress:  newAddressFunc,
	})
	if err != nil {
		return nil, err
	}
	s.connManager = cmgr

	return &s, nil
}

func (s *Client) AddServiceNode(node *sn.ServiceNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only support EXR node connections
	if !node.EXRCompatible() {
		return
	}
	s.servicenodes = append(s.servicenodes, node)
	for k, _ := range node.Services() {
		s.services[k] = append(s.services[k], node)
	}
}

func (s *Client) WaitForService(timeoutMsec uint32, service string, query int) error {
	var msec uint32 = 0
	for {
		s.mu.Lock()
		snodes1, ok1 := s.services[addNamespace(service, true)]
		snodes2, ok2 := s.services[addNamespace(service, false)]
		s.mu.Unlock()
		if !ok1 && !ok2 && len(snodes1) < query && len(snodes2) < query {
			time.Sleep(100 * time.Millisecond)
			msec += 100
			if msec >= timeoutMsec {
				return errors.New("timeout waiting for service")
			}
		} else {
			break
		}
	}
	return nil
}

func (s *Client) GetBlockCountRaw(service string, query int) (string, []SnodeReply, error) {
	uid := uuid.New().String()
	nsservice := addNamespace(service, true)

	// lookup service nodes for token
	snodes, err := s.snodesForService(nsservice, true)
	if len(snodes) <= 0 || err != nil {
		return uid, []SnodeReply{}, fmt.Errorf("no services for token %s", nsservice)
	}

	// fetch EXR compatible snodes
	replies, err := fetchDataFromSnodes(&snodes, fmt.Sprintf("/xr/%s/xrGetBlockCount", removeNamespace(nsservice)), query)
	if len(replies) <= 0 {
		return uid, []SnodeReply{}, errors.New("no replies found")
	}
	return uid, replies, nil
}

func (s *Client) WaitForXRouter(ctx context.Context) (bool, error) {
	select {
	case isReady := <-s.ready:
		return isReady, nil
	case <-s.interrupt:
		return false, errors.New("XRouter timeout, interrupt received")
	case <-s.quit:
		return false, errors.New("XRouter timeout, shutdown requested")
	case <-ctx.Done():
		return false, errors.New("XRouter timeout, failed to connect")
	}
}

// addKnownAddresses adds the given addresses to the set of known addresses to
// the peer to prevent sending duplicate addresses.
func (s *Client) addKnownAddresses(addresses []*wire.NetAddress) {
	s.mu.Lock()
	for _, na := range addresses {
		s.knownAddresses[addrmgr.NetAddressKey(na)] = struct{}{}
	}
	s.mu.Unlock()
}

// addressKnown true if the given address is already known to the peer.
func (s *Client) addressKnown(na *wire.NetAddress) bool {
	s.mu.Lock()
	_, exists := s.knownAddresses[addrmgr.NetAddressKey(na)]
	s.mu.Unlock()
	return exists
}

func (s *Client) snodesForService(service string, spv bool) ([]*sn.ServiceNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	serv := addNamespace(service, spv)
	snodes, ok := s.services[serv]
	if !ok {
		return []*sn.ServiceNode{}, errors.New("no service nodes found for " + serv)
	}
	return snodes, nil
}

// removeNamespace removes the XRouter namespace (e.g. xr::, xrs::)
func removeNamespace(ns string) string {
	if strings.HasPrefix(ns, xr) {
		return strings.TrimPrefix(ns, xr)
	} else if strings.HasPrefix(ns, xrs) {
		return strings.TrimPrefix(ns, xrs)
	}
	return ns
}

// addNamespace adds the XRouter namespace (e.g. xr::, xrs::)
func addNamespace(ns string, spv bool) string {
	if spv && !strings.HasPrefix(ns, xr) {
		return xr + ns
	} else if !spv && !strings.HasPrefix(ns, xrs) {
		return xrs + ns
	}
	return ns
}

// fetchDataFromSnodes queries N number of service nodes and returns the results.
func fetchDataFromSnodes(snodes *[]*sn.ServiceNode, path string, query int) ([]SnodeReply, error) {
	// TODO Blocknet penalize bad snodes
	var replies []SnodeReply
	queried := 0
	for _, snode := range *snodes {
		if !snode.EXRCompatible() {
			continue
		}

		strPubkey := hex.EncodeToString(snode.Pubkey().SerializeCompressed())

		res, err := http.Get(snode.EndpointPath(path))
		if err != nil {
			log.Printf("failed to connect to snode %v %v", strPubkey, err)
			continue
		}
		if res.StatusCode != http.StatusOK {
			log.Printf("bad response from snode: %v %v", strPubkey, res.Status)
			_ = res.Body.Close()
			continue
		}

		// Read response data, hash it and record unique responses
		data, err := ioutil.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil {
			log.Printf("unable to read response from snode %v", strPubkey)
			continue
		}

		// Compute hash for reply
		hash := sha1.New()
		_, err = hash.Write(data)
		if err != nil {
			continue
		}

		// Store reply and exit if reply count is met
		replies = append(replies, SnodeReply{snode.Pubkey().SerializeCompressed(), hash.Sum(nil), data})
		queried += 1
		if queried >= query {
			break
		}
	}

	if len(replies) <= 0 {
		return replies, errors.New("replies ")
	}
	return replies, nil
}

// MostCommonReply returns the most common reply from the reply list
func MostCommonReply(replies []SnodeReply) (SnodeReply, error) {
	snodeDataCounts := make(map[string]int)
	for _, reply := range replies {
		snodeDataCounts[string(reply.Hash)] += 1
	}

	snodeDataLen := len(snodeDataCounts)
	if snodeDataLen == 0 { // no result
		return SnodeReply{}, errors.New("no replies found")
	}
	if snodeDataLen == 1 { // single result
		return replies[0], nil
	}

	// Return the most common result
	lastCount := 0
	lastHashStr := ""
	for k, v := range snodeDataCounts {
		if v > lastCount {
			lastCount = v
			lastHashStr = k
		}
	}
	for _, reply := range replies {
		if string(reply.Hash) == lastHashStr {
			return reply, nil
		}
	}

	return SnodeReply{}, errors.New("no replies found (b)")
}
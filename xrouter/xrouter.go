// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package xrouter

import (
	"bytes"
	"context"
	"crypto/sha1"
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
	defaultTargetOutbound,
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
	ready          chan struct{}
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
	xrouterReady   int32
}

func NewClient(params chaincfg.Params) (*Client, error) {
	s := Client{}
	s.params = &params
	s.services = make(map[string][]*sn.ServiceNode)
	s.mu = sync.Mutex{}
	s.addrManager = addrmgr.New(".", btcdLookup)
	s.newPeers = make(chan *serverPeer, cfg.MaxPeers)
	s.donePeers = make(chan *serverPeer, cfg.MaxPeers)
	s.banPeers = make(chan *serverPeer, cfg.MaxPeers)
	s.broadcast = make(chan broadcastMsg, cfg.MaxPeers)
	s.quit = make(chan struct{})
	s.ready = make(chan struct{})
	s.query = make(chan interface{})
	s.interrupt = interruptListener()
	// Create a connection manager.
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

			// only allow recent nodes (10mins) after we failed 30
			// times
			if tries < 30 && time.Since(addr.LastAttempt()) < 10*time.Minute {
				continue
			}

			// allow nondefault ports after 50 failed tries.
			if tries < 50 && fmt.Sprintf("%d", addr.NetAddress().Port) !=
				s.params.DefaultPort {
				continue
			}

			// Mark an attempt for the valid address.
			s.addrManager.Attempt(addr.NetAddress())

			addrString := addrmgr.NetAddressKey(addr.NetAddress())
			if s.connManager.HasConnection(addrString) {
				continue
			}
			return addrStringToNetAddr(addrString)
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

func (s *Client) WaitForService(timeoutMsec uint32, service string, serviceCount uint32) error {
	return nil
}

func (s *Client) GetBlockCountRaw(token string, querynodes uint32) (string, string, error) {
	uid := uuid.New().String()
	// lookup service nodes for token
	snodes, ok := s.services["xr::"+token] // TODO Blocknet token parser (accept BLOCK, xr::BLOCK, etc)
	if !ok {
		return "", uid, fmt.Errorf("no services for token %s", token)
	}

	// fetch EXR compatible snodes
	result, err := fetchDataFromSnodes(&snodes, fmt.Sprintf("/xr/%s/xrGetBlockCount", token))
	return uid, result, err
}

func (s *Client) WaitForXRouter(ctx context.Context) error {
out:
	for {
		select {
		case <-s.ready:
			break out
		case <-s.interrupt:
			return errors.New("XRouter timeout, interrupt received")
		case <-s.quit:
			return errors.New("XRouter timeout, shutdown requested")
		case <-ctx.Done():
			return errors.New("XRouter timeout, failed to connect")
		}
	}
	return nil
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

/*func (s *Client) connectToSeedNode(params chaincfg.Params) error {
	verack := make(chan struct{})
	peerCfg := &peer.Config{
		UserAgentName:    "exrbtcd",  // User agent name to advertise.
		UserAgentVersion: "4.2.0", // User agent version to advertise.
		ChainParams:      &params,
		Services:         0,
		TrickleInterval:  time.Second * 10,
		Listeners: peer.MessageListeners{
			OnVersion: func(p *peer.Peer, msg *wire.MsgVersion) *wire.MsgReject {
				fmt.Println("outbound: received version")
				return nil
			},
			OnVerAck: func(p *peer.Peer, msg *wire.MsgVerAck) {
				verack <- struct{}{}
			},
			OnAddr: func(p *peer.Peer, msg *wire.MsgAddr) {
				// A message that has no addresses is invalid.
				if len(msg.AddrList) == 0 {
					p.Disconnect()
					return
				}

				for _, na := range msg.AddrList {
					// Don't add more address if we're disconnecting.
					if !p.Connected() {
						return
					}

					// Set the timestamp to 5 days ago if it's more than 24 hours
					// in the future so this address is one of the first to be
					// removed when space is needed.
					now := time.Now()
					if na.Timestamp.After(now.Add(time.Minute * 10)) {
						na.Timestamp = now.Add(-1 * time.Hour * 24 * 5)
					}

					// Add address to known addresses for this peer.
					s.addKnownAddresses([]*wire.NetAddress{na})
				}

				// Add addresses to server address manager.  The address manager handles
				// the details of things such as preventing duplicate addresses, max
				// addresses, and last seen updates.
				// XXX bitcoind gives a 2 hour time penalty here, do we want to do the
				// same?
				s.addrManager.AddAddresses(msg.AddrList, sp.NA())
			},
		},
	}

	if len(params.DNSSeeds) == 0 {
		return errors.New("at least 1 dns seed node needs to be specified")
	}

	p, err := peer.NewOutboundPeer(peerCfg, params.DNSSeeds[0].Host + ":" + params.DefaultPort)
	if err != nil {
		fmt.Printf("NewOutboundPeer: error %v\n", err)
		return errors.New("failed to connect to seed node")
	}

	// Establish the connection to the peer address and mark it connected.
	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		fmt.Printf("net.Dial: error %v\n", err)
		return errors.New("failed to connect to seed node")
	}
	p.AssociateConnection(conn)

	// Wait for the verack message or timeout in case of failure.
	select {
	case <-verack:
	case <-time.After(time.Second * 15):
		fmt.Printf("seed node connection timeout, no verack")
	}

	// Disconnect the peer.
	p.Disconnect()
	p.WaitForDisconnect()

	return nil
}*/

func fetchDataFromSnodes(snodes *[]*sn.ServiceNode, endpoint string) (string, error) {
	var hashstr string
	snodeDataCounts := make(map[string]int)
	snodeData := make(map[string][]byte)
	for _, snode := range *snodes {
		if !snode.EXRCompatible() {
			continue
		}

		res, err := http.Get(snode.Endpoint())
		if err != nil { // TODO Blocknet penalize bad snodes
			if err != nil {
				log.Fatal(err)
			}
			continue
		}
		if res.StatusCode != http.StatusOK {
			log.Fatalf("bad response from snode %v", res.Status)
			res.Body.Close()
			continue
		}

		// read response data, hash it and record unique responses
		data, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			log.Fatalf("unable to read snode response %v", string(snode.Pubkey().SerializeCompressed()))
			continue
		}

		hash := sha1.New()
		hash.Write(data)
		hashstr = string(hash.Sum(nil))

		snodeDataCounts[hashstr] += 1
		if _, ok := snodeData[hashstr]; !ok {
			snodeData[hashstr] = data
		}
	}

	snodeDataLen := len(snodeData)
	if snodeDataLen == 0 { // no result
		return "", nil
	}

	if snodeDataLen == 1 { // single result
		return string(snodeData[hashstr]), nil
	}

	// return the most common result
	lastCount := 0
	lastHashStr := ""
	for k, v := range snodeDataCounts {
		if v > lastCount {
			lastCount = v
			lastHashStr = k
		}
	}
	if data, ok := snodeData[lastHashStr]; ok {
		return string(data), nil
	}

	return "", nil
}

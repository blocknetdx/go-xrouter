// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package xrouter

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/blocknetdx/go-xrouter/sn"
	"github.com/btcsuite/btcd/addrmgr"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/connmgr"
	"github.com/btcsuite/btcd/wire"
	"github.com/google/uuid"
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

// XRouter namespaces
const (
	xr      string = "xr"
	xrs     string = "xrs"
	xrd     string = "xrd" // domain
	xrdelim string = "::"
)

// XRouter SPV calls
const (
	xrGetBlockCount     string = "xrGetBlockCount"
	xrGetBlockHash      string = "xrGetBlockHash"
	xrGetBlock          string = "xrGetBlock"
	xrGetBlocks         string = "xrGetBlocks"
	xrGetTransaction    string = "xrGetTransaction"
	xrGetTransactions   string = "xrGetTransactions"
	xrDecodeTransaction string = "xrDecodeTransaction"
	xrSendTransaction   string = "xrSendTransaction"
)

// XRouter Non-SPV calls
const (
	xrsService string = "xrService"
)

// xrNS return the XRouter namespace with delimiter.
func xrNS(ns string) string {
	return ns + xrdelim
}

// isNS returns true if the service matches the namespace.
func isNS(service, ns string) bool {
	return strings.HasPrefix(service, ns+xrdelim)
}

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
	Pubkey      []byte
	Hash        []byte
	Reply       []byte
	ParsedReply string
	IP          string
}

type MCR struct {
	Consensus  Consensus
	QueryCount string
}

type Consensus struct {
	MajorityStrength     string
	MostCommonReplyCount int
	MostCommonReply      string
	DivergentReplyCount  int
	DivergentReplies     []DivergentReply
}

type DivergentReply struct {
	Count int
	Reply string
}

type Config struct {
	MaxPeers       int
	SimNet         bool
	DisableBanning bool
	BanThreshold   uint32
	BanDuration    time.Duration
	DataDir        string
	AddPeers       []string
	ConnectPeers   []string
	whitelists     []*net.IPNet
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
	servicenodes   map[string]*sn.ServiceNode
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
	shutdownSched  int32    // list of blacklisted substrings by which to filter user agents
	agentBlacklist []string // list of whitelisted user agent substrings, no whitelisting will be applied if the list is empty or nil
	agentWhitelist []string
	startupTime    int64
	bytesReceived  uint64 // Total bytes received from all peers since start
	bytesSent      uint64 // Total bytes sent by all peers since start
	storage        *sn.SNodeStorage
}

// NewClient creates and returns a new XRouter client.
func NewClient(params chaincfg.Params) (*Client, error) {
	s := Client{}
	s.params = &params
	s.servicenodes = make(map[string]*sn.ServiceNode)
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
	s.storage = sn.NewSNodeStorage("nodes.json")
	s.storage.Load()
	// time.Sleep(10 * time.Minute)
	return &s, nil
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

// WaitForServices will block until the specified services become available or the
// context timeout occurs. This is useful to prevent code from executing until the
// network service is found. By default this method will check for the existence
// of a service every 100 milliseconds.
func (s *Client) WaitForServices(ctx context.Context, services []string, query int) error {
	// Check all snode services for the requested service (and query count).
	doneChan := make(chan struct{}, 1)
	for {
		ready := true
		for _, service := range services {
			s.mu.Lock()
			snodes1, ok1 := s.services[addNamespace(service, xr)]
			snodes2, ok2 := s.services[addNamespace(service, xrs)]
			s.mu.Unlock()
			ready = ready && (ok1 || ok2) && (len(snodes1) >= query || len(snodes2) >= query)
		}

		if ready { // Notify channel if all services are ready
			doneChan <- struct{}{}
		}

		select {
		case <-doneChan:
			return nil // ready
		case <-ctx.Done():
			return errors.New("timeout waiting for service")
		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// AddServiceNode adds the specified service node to the client's list. Only EXR snodes
// are added. Any services that do not support Enterprise XRouter are not added.
func (s *Client) AddServiceNode(node *sn.ServiceNode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only support EXR node connections
	if !node.EXRCompatible() {
		return
	}
	// Check if snode already exists
	pkey := hex.EncodeToString(node.Pubkey().SerializeCompressed())
	if _, ok := s.servicenodes[pkey]; ok {
		return
	}
	s.servicenodes[pkey] = node
	for k, _ := range node.Services() {
		s.services[k] = append(s.services[k], node)
	}
	s.storage.Add(pkey, node)
}

// ListNetworkServices lists all known SPV and XCloud network services (xr and xrs).
func (s *Client) ListNetworkServices() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var services []string
	for k, _ := range s.services {
		services = append(services, k)
	}
	return services
}

// HasNetworkService returns true if the network service was found. If no namespace
// is specified the SPV namespace will be searched followed by the xrs namespace.
func (s *Client) HasNetworkService(service string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	// If namespace was provided
	if isNS(service, xr) || isNS(service, xrs) {
		return true
	}
	// If namespace was not provided, check SPV first
	_, ok := s.services[addNamespace(service, xr)]
	if !ok {
		// Check non-SPV services
		_, ok = s.services[addNamespace(service, xrs)]
	}
	return ok
}

// HasSPVService returns true if the SPV network service was found for the specified
// token.
func (s *Client) HasSPVService(service string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.services[addNamespace(service, xr)]
	return ok
}

// GetBlockCountRaw SPV call fetches the block count (chain height) of the specified token.
// Returns all replies.
func (s *Client) GetBlockCountRaw(service string, query int) (string, []SnodeReply, error) {
	return callFetchWrapper(s, service, xrGetBlockCount, nil, query, xr)
}

// GetBlockCount SPV call fetches the block count (chain height) of the specified token.
// Returns the most common reply.
func (s *Client) GetBlockCount(service string, query int) (*MCR, error) {
	if _, replies, err := s.GetBlockCountRaw(service, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrGetBlockCount)
	}
}

// GetBlockHashRaw SPV call fetches the block hash with the specified block number.
// Returns all replies.
func (s *Client) GetBlockHashRaw(service string, block interface{}, query int) (string, []SnodeReply, error) {
	var params []interface{}
	if val, ok := block.(int); ok { // if int
		params = append(params, val)
	} else if val, ok := block.(string); ok { // if hex
		params = append(params, val)
	} else {
		return "", nil, errors.New("unexpected type: only int and hex string supported")
	}
	return callFetchWrapper(s, service, xrGetBlockHash, params, query, xr)
}

// GetBlockHash SPV call fetches the block hash with the specified block number.
// Returns the most common reply.
func (s *Client) GetBlockHash(service string, block interface{}, query int) (*MCR, error) {
	if _, replies, err := s.GetBlockHashRaw(service, block, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrGetBlockHash)
	}
}

// GetBlockRaw fetches the block data by block hash or block height. Returns all replies.
func (s *Client) GetBlockRaw(service string, block interface{}, query int) (string, []SnodeReply, error) {
	var params []interface{}
	if val, ok := block.(int); ok { // if int
		params = append(params, val)
	} else if val, ok := block.(string); ok { // if hex
		params = append(params, val)
	} else {
		return "", nil, errors.New("unexpected type: only int and hex string supported")
	}
	return callFetchWrapper(s, service, xrGetBlock, params, query, xr)
}

// GetBlock fetches the block data by block hash or block height. Returns the most common
// reply.
func (s *Client) GetBlock(service string, block interface{}, query int) (*MCR, error) {
	if _, replies, err := s.GetBlockRaw(service, block, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrGetBlock)
	}
}

// GetBlocks fetches the blocks by block hash or block height. Returns all replies.
func (s *Client) GetBlocksRaw(service string, blocks []interface{}, query int) (string, []SnodeReply, error) {
	// Check parameters
	for _, v := range blocks {
		if _, ok := v.(int); ok { // if int
			continue
		} else if _, ok := v.(string); ok { // if hex
			continue
		} else {
			return "", nil, errors.New("unexpected type: only int and hex string supported")
		}
	}
	return callFetchWrapper(s, service, xrGetBlocks, blocks, query, xr)
}

// GetBlocks fetches the blocks by block hash or block height. Returns the most common
// reply.
func (s *Client) GetBlocks(service string, blocks []interface{}, query int) (*MCR, error) {
	if _, replies, err := s.GetBlocksRaw(service, blocks, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrGetBlocks)
	}
}

// GetTransactionRaw fetches the transaction by hash or transaction id. Returns all replies.
func (s *Client) GetTransactionRaw(service string, txid interface{}, query int) (string, []SnodeReply, error) {
	var params []interface{}
	if val, ok := txid.(int); ok { // if int
		params = append(params, val)
	} else if val, ok := txid.(string); ok { // if hex
		params = append(params, val)
	} else {
		return "", nil, errors.New("unexpected type: only int and hex string supported")
	}
	return callFetchWrapper(s, service, xrGetTransaction, params, query, xr)
}

// GetTransaction fetches the transaction by hash or transaction id. Returns the most common
// reply.
func (s *Client) GetTransaction(service string, block interface{}, query int) (*MCR, error) {
	if _, replies, err := s.GetTransactionRaw(service, block, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrGetTransaction)
	}
}

// GetTransactionsRaw fetches the transactions by hash or transaction id. Returns all replies.
func (s *Client) GetTransactionsRaw(service string, txids []interface{}, query int) (string, []SnodeReply, error) {
	// Check parameters
	for _, v := range txids {
		if _, ok := v.(int); ok { // if int
			continue
		} else if _, ok := v.(string); ok { // if hex
			continue
		} else {
			return "", nil, errors.New("unexpected type: only int and hex string supported")
		}
	}
	return callFetchWrapper(s, service, xrGetTransactions, txids, query, xr)
}

// GetTransactions fetches the transactions by hash or transaction id. Returns the most common
// reply.
func (s *Client) GetTransactions(service string, txids []interface{}, query int) (*MCR, error) {
	if _, replies, err := s.GetTransactionsRaw(service, txids, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrGetTransactions)
	}
}

// DecodeTransactionRaw fetches the transaction data by hash or transaction id. Returns all replies.
func (s *Client) DecodeTransactionRaw(service string, txhex interface{}, query int) (string, []SnodeReply, error) {
	var params []interface{}
	if val, ok := txhex.([]byte); ok { // if byte array
		params = append(params, string(val))
	} else if val, ok := txhex.(string); ok { // if hex
		params = append(params, val)
	} else {
		return "", nil, errors.New("unexpected type: only byte array and hex string supported")
	}
	return callFetchWrapper(s, service, xrDecodeTransaction, params, query, xr)
}

// DecodeTransaction fetches the transaction data by hash or transaction id. Returns the most common
// reply.
func (s *Client) DecodeTransaction(service string, txhex interface{}, query int) (*MCR, error) {
	if _, replies, err := s.DecodeTransactionRaw(service, txhex, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrDecodeTransaction)
	}
}

// SendTransactionRaw submits a transaction to the network of the specified token. Returns all replies.
func (s *Client) SendTransactionRaw(service string, txhex interface{}, query int) (string, []SnodeReply, error) {
	var params []interface{}
	if val, ok := txhex.([]byte); ok { // if byte array
		params = append(params, string(val))
	} else if val, ok := txhex.(string); ok { // if hex
		params = append(params, val)
	} else {
		return "", nil, errors.New("unexpected type: only byte array and hex string supported")
	}
	return callFetchWrapper(s, service, xrSendTransaction, params, query, xr)
}

// SendTransaction submits a transaction to the network of the specified token. Returns the most common
// reply.
func (s *Client) SendTransaction(service string, txhex interface{}, query int) (*MCR, error) {
	if _, replies, err := s.SendTransactionRaw(service, txhex, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrSendTransaction)
	}
}

// CallServiceRaw submits requests to [query] number of endpoints. All replies are
// returned.
func (s *Client) CallServiceRaw(service string, params []interface{}, query int) (string, []SnodeReply, error) {
	return callFetchWrapper(s, service, xrsService, params, query, xrs)
}

// CallService submits requests to [query] number of endpoints. The most common reply
// is returned.
func (s *Client) CallService(service string, params []interface{}, query int) (*MCR, error) {
	if _, replies, err := s.CallServiceRaw(service, params, query); err != nil {
		return nil, err
	} else {
		return s.MostCommonReply(replies, query, service, xrsService)
	}
}

// GetSnodeList
func (s *Client) GetSnodeList() []*sn.ExportedServiceNode {
	return s.storage.List()
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

// snodesForService returns all service nodes that support the specified service.
func (s *Client) snodesForService(service, ns string) ([]*sn.ServiceNode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	serv := addNamespace(service, ns)
	snodes, ok := s.services[serv]
	if !ok {
		return []*sn.ServiceNode{}, errors.New("no service nodes found for " + serv)
	}
	return snodes, nil
}

// MostCommonReply returns the most common reply from the reply list
func (s *Client) MostCommonReply(replies []SnodeReply, query int, service, requestName string) (*MCR, error) {
	mcr := &MCR{}
	consensus := Consensus{}

	snodeDataCounts := make(map[string]int)
	uniqueReplies := make([]SnodeReply, 0)
	for _, reply := range replies {
		if _, ok := snodeDataCounts[string(reply.Hash)]; !ok {
			uniqueReplies = append(uniqueReplies, reply)
		}
		snodeDataCounts[string(reply.Hash)] += 1
	}

	snodeDataLen := len(replies)

	message := fmt.Sprintf(
		`Failed to find enough peers supporting %s
		for %s whose fees fall within the limits set in your config file. 
		You requested responses from %d nodes, but only got %d. 
		Please try to connect to more peers before retrying the request.`,
		requestName, service, query, snodeDataLen)

	if snodeDataLen == 0 { // no result
		mcr.QueryCount = message
		return mcr, errors.New("no replies found (b)")
	}

	if snodeDataLen == 1 { // single result
		if query > 1 {
			mcr.QueryCount = message
		}

		consensus.MostCommonReplyCount = snodeDataCounts[string(replies[0].Hash)]
		consensus.MostCommonReply = replies[0].ParsedReply
		consensus.MajorityStrength = "100%"
		mcr.Consensus = consensus
		return mcr, nil
	}

	type responsePair struct {
		count int
		reply SnodeReply
	}

	uniqueCount := make(map[string]responsePair)

	for _, _reply := range uniqueReplies {
		_h := hashResponse(_reply.Reply)
		if pair, ok := uniqueCount[_h]; ok {
			// found existing hash!
			_c := pair.count + 1
			pair.count = _c
			uniqueCount[_h] = pair
		} else {
			newPair := responsePair{
				count: 1,
				reply: _reply,
			}
			uniqueCount[_h] = newPair
		}
	}

	// find most common (actually with the height count)
	maxKey := ""
	maxValue := 0
	for k, v := range uniqueCount {
		if v.count > maxValue {
			maxValue = v.count
			maxKey = k
		}
	}

	// check if there two equal counts (:
	equalExist := false
	for k, v := range uniqueCount {
		if v.count == maxValue && maxKey != k {
			equalExist = true
			break
		}
	}

	// fix here
	if !equalExist {
		consensus.MostCommonReplyCount = snodeDataCounts[string(uniqueCount[maxKey].reply.Hash)]
		consensus.MostCommonReply = uniqueCount[maxKey].reply.ParsedReply
	}
	consensus.DivergentReplies = make([]DivergentReply, 0)
	if len(replies) != maxValue {
		// we found divergents
		for k, v := range uniqueCount {
			if k != maxKey || equalExist {
				// actual divirgent
				consensus.DivergentReplies = append(consensus.DivergentReplies, DivergentReply{
					Count: snodeDataCounts[string(v.reply.Hash)],
					Reply: v.reply.ParsedReply,
				})

				// remove divergent nodes
				s.storage.Remove(string(v.reply.Pubkey), v.reply.IP)
			}
		}
	}
	consensus.DivergentReplyCount = len(consensus.DivergentReplies)
	if len(replies) != query {
		mcr.QueryCount = message
	}
	majorityStrength := float32(consensus.MostCommonReplyCount) / float32(len(replies)) * 100

	if majorityStrength < 0.5 {
		// remove everything, since the majorityCount is just too low
		for _, v := range uniqueReplies {
			s.storage.Remove(string(v.Pubkey), v.IP)
		}
	}
	consensus.MajorityStrength = fmt.Sprintf("%.2f%%",
		majorityStrength,
	)

	mcr.Consensus = consensus
	return mcr, nil
}

// removeNamespace removes the XRouter namespace (e.g. removes xr:: xrs::)
func removeNamespace(service string) string {
	if isNS(service, xr) {
		return strings.TrimPrefix(service, xrNS(xr))
	} else if isNS(service, xrs) {
		return strings.TrimPrefix(service, xrNS(xrs))
	}
	return service
}

// addNamespace adds the XRouter namespace (e.g. xr::, xrs::)
func addNamespace(service, ns string) string {
	if !isNS(service, ns) {
		return xrNS(ns) + service
	}
	return service
}

// callFetchWrapper Performs a lookup on the requested XRouter service and submits the request
// to the desired number of snodes.
func callFetchWrapper(s *Client, service string, xrfunc string, params []interface{}, query int, ns string) (string, []SnodeReply, error) {
	uid := uuid.New().String()
	nsservice := addNamespace(service, ns)

	// lookup service nodes for token
	snodes, err := s.snodesForService(nsservice, ns)
	if len(snodes) <= 0 || err != nil {
		return uid, []SnodeReply{}, fmt.Errorf("no services for token %s", nsservice)
	}

	// fetch EXR compatible snodes
	var endpoint string
	if ns == xr {
		endpoint = fmt.Sprintf("/%s/%s/%s", ns, removeNamespace(nsservice), xrfunc)
	} else { // xrs namespace
		endpoint = fmt.Sprintf("/%s/%s", ns, removeNamespace(nsservice))
	}
	replies, err := s.fetchDataFromSnodes(&snodes, endpoint, params, query)
	if len(replies) <= 0 {
		return uid, []SnodeReply{}, nil
	}
	return uid, replies, nil
}

// fetchDataFromSnodes queries N number of service nodes and returns the results.
type FetchDataError struct {
	Error fetchErrorInternal `json:"error"`
	Code  int                `json:"code"`
	ID    int                `json:"id"`
}

type fetchErrorInternal struct {
	Code    int    `json:"code"`
	Message string `json:"string"`
}

type FetchDataErrorSimple struct {
	Error string `json:"error"`
	Code  int    `json:"code"`
}

// "{\"result\": null, \"error\": {\"code\": -28, \"message\": \"Rewinding blocks...\"}, \"id\": 1}"

func (s *Client) fetchDataFromSnodes(snodes *[]*sn.ServiceNode, path string, params []interface{}, query int) ([]SnodeReply, error) {
	// TODO Blocknet penalize bad snodes
	var replies []SnodeReply
	var wg sync.WaitGroup
	var mu sync.Mutex
	queried := 0
	validResults := 0
	uniqueNodes := make(map[string]struct{})
	for _, snode := range *snodes {
		if !snode.EXRCompatible() {
			continue
		}

		queried++
		wg.Add(1)

		// Query from as many snodes as possible up to requested query count
		go func(snode *sn.ServiceNode) {
			defer wg.Done()
			// bad := false
			var err error

			strPubkey := hex.EncodeToString(snode.Pubkey().SerializeCompressed())

			// Prep parameters for post
			var dataPost []byte
			if len(params) > 0 {
				dataPost, err = json.Marshal(params)
				if err != nil {
					mu.Lock()
					queried--
					mu.Unlock()
					return
				}
			}

			bufPost := bytes.NewBuffer(dataPost)
			endpoint := snode.EndpointPath(path) // Post parameters along with the request
			res, err := http.Post(endpoint, "application/json", bufPost)
			if err != nil {
				log.Printf("failed to connect to snode %v %v", strPubkey, err)
				mu.Lock()
				queried--
				mu.Unlock()
				return
			}

			if res.StatusCode != http.StatusOK {
				log.Printf("bad response from snode: %v %v", strPubkey, res.Status)
				_ = res.Body.Close()
				// bad = true
				// ignore bad response
				mu.Lock()
				queried--
				mu.Unlock()
				return
			}

			// Read response data, hash it and record unique responses
			data, err := ioutil.ReadAll(res.Body)
			_ = res.Body.Close()
			if err != nil {
				log.Printf("unable to read response from snode %v", strPubkey)
				mu.Lock()
				queried--
				mu.Unlock()
				return
			}

			if len(data) == 0 || data == nil {
				// We got an empty reply
				mu.Lock()
				queried--
				mu.Unlock()
				return
			}

			// Compute hash for reply
			hash := sha1.New()
			_, err = hash.Write(data)
			if err != nil {
				mu.Lock()
				queried--
				mu.Unlock()
				return
			}

			// Check for json error and try another snode if there's an error
			var jsonErr FetchDataError
			if err := json.Unmarshal(data, &jsonErr); err == nil && jsonErr.Code != 0 {
				mu.Lock()
				queried--
				mu.Unlock()
				return
				// store this error below (no return here)
			} else {
				mu.Lock()
				validResults++
				mu.Unlock()
			}

			var jsonErrSimple FetchDataErrorSimple
			if err := json.Unmarshal(data, &jsonErrSimple); err == nil && jsonErr.Code != 0 {
				mu.Lock()
				queried--
				mu.Unlock()
				return
				// store this error below (no return here)
			} else {
				mu.Lock()
				validResults++
				mu.Unlock()
			}

			_ = s.queryXrShowConfigs(snode)
			s.storage.AddCount(strPubkey, snode)

			mu.Lock()
			if _, ok := uniqueNodes[snode.Endpoint()]; ok {
				mu.Unlock()
				return
			}
			uniqueNodes[snode.Endpoint()] = struct{}{}
			replies = append(replies, SnodeReply{snode.Pubkey().SerializeCompressed(), hash.Sum(nil), data, string(data), snode.HostIP()})
			mu.Unlock()
		}(snode)

		// Wait for error, if error try another snode.
		if queried >= query {
			wg.Wait()
		}
		if validResults >= query {
			break // have all our data
		}
	}
	wg.Wait()

	if len(replies) <= 0 {
		return replies, errors.New("no replies found")
	}
	return replies, nil
}

func (s *Client) queryXrShowConfigs(node *sn.ServiceNode) bool {
	pubkey := hex.EncodeToString(node.Pubkey().SerializeCompressed())
	path := "/xrshowconfigs"
	var dataPost []byte

	bufPost := bytes.NewBuffer(dataPost)
	endpoint := node.EndpointPath(path) // Post parameters along with the request
	res, err := http.Post(endpoint, "application/json", bufPost)
	if err != nil {
		log.Printf("xrshowconfigs: failed to connect to snode %v %v", pubkey, err)
		return false
	}

	if res.StatusCode != http.StatusOK {
		log.Printf("xrshowconfigs: bad response from snode: %v %v", pubkey, res.Status)
		_ = res.Body.Close()
		return false
	}

	// Read response data, hash it and record unique responses
	data, err := ioutil.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil {
		log.Printf("xrshowconfigs: unable to read response from snode %v", pubkey)
		return false
	}

	if len(data) == 0 || data == nil {
		// We got an empty reply
		return false
	}

	// Compute hash for reply
	hash := sha1.New()
	_, err = hash.Write(data)
	if err != nil {
		return false
	}

	// Check for json error and try another snode if there's an error
	var jsonErr FetchDataError
	if err := json.Unmarshal(data, &jsonErr); err == nil && jsonErr.Code != 0 {
		return false
		// store this error below (no return here)
	}

	var jsonErrSimple FetchDataErrorSimple
	if err := json.Unmarshal(data, &jsonErrSimple); err == nil && jsonErr.Code != 0 {
		return false
		// store this error below (no return here)
	}
	var response []*sn.XRShowConfigsResponse
	if err := json.Unmarshal([]byte(data), &response); err != nil {
		panic(err)
	}
	for _, v := range response {
		snode, err := sn.NewServiceNodeFromConfig(v.Config)
		if err != nil {
			continue
		}
		s.storage.Add(pubkey, snode)
	}
	return true
}

func hashResponse(response []byte) string {
	h := sha1.New()
	h.Write([]byte(response))
	return hex.EncodeToString(h.Sum(nil))
}

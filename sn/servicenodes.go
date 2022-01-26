// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sn

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
)

type ServiceNode struct {
	pubkey        *btcec.PublicKey
	host          string
	port          int
	hostIP        net.IP
	tls           bool
	endpoint      string
	exrCompatible bool
	services      map[string]bool

	score          int  // no info
	banned         bool // no info
	paymentAddress string
	spWallets      []string
	spvconfigs     []*SpvConfig
	feedefault     float64
	// fees
	xrouter     bool
	servicenode bool
	config      string // working -- removed for the sake of output
	plugins     map[string]string
}

type SpvConfig struct {
	spvwallet string
	commands  []*SpvCommand
}

type SpvCommand struct {
	command        string
	fee            float64
	requestLimit   int
	paymentAddress string
	disabled       bool
}

type ServiceNodeConfigXRouter struct {
	Config  string            `json:"config,omitempty"`
	Plugins map[string]string `json:"plugins,omitempty"`
}
type ServiceNodeConfig struct {
	XRouterVersion int32                    `json:"xrouterversion,omitempty"`
	XBridgeVersion int32                    `json:"xbridgeversion,omitempty"`
	XRouter        ServiceNodeConfigXRouter `json:"xrouter,omitempty"`
	XBridge        []string                 `json:"xbridge,omitempty"`
}

var (
	reWallets  = regexp.MustCompile("\\s*wallets\\s*=\\s*([a-zA-Z0-9$,_]+)\\s*$")
	rePlugins  = regexp.MustCompile("\\s*plugins\\s*=\\s*([a-zA-Z0-9$,_]+)\\s*$")
	reHost     = regexp.MustCompile("\\s*host\\s*=\\s*([a-zA-Z0-9\\.]+)\\s*$")
	rePort     = regexp.MustCompile("\\s*port\\s*=\\s*(\\d+)\\s*$")
	reTls      = regexp.MustCompile("\\s*tls\\s*=\\s*([^\\s]+)\\s*$")
	rePayment  = regexp.MustCompile("\\s*paymentaddress\\s*=\\s*([a-zA-Z0-9]+)\\s*$")
	reFee      = regexp.MustCompile("\\s*fee\\s*=\\s*([0-9\\.]+)\\s*$")
	reRequest  = regexp.MustCompile("\\s*requestlimit\\s*=\\s*([0-9]+)\\s*$")
	reDisabled = regexp.MustCompile("\\s*disabled\\s*=\\s*([0-9]+)\\s*$")
)

func NewServiceNode(pubkey *btcec.PublicKey, config string) (*ServiceNode, error) {
	s := ServiceNode{}
	s.pubkey = pubkey
	s.services = make(map[string]bool)

	// Parse config
	var snconf ServiceNodeConfig
	if err := json.Unmarshal([]byte(config), &snconf); err != nil {
		log.Println(err)
		return nil, errors.New("failed to parse the service node config")
	}

	confBytes := []byte(snconf.XRouter.Config)
	buf := bytes.NewBuffer(confBytes)
	scanner := bufio.NewScanner(buf)
	firstFee := true

	// commands

	commandsToWallets := make(map[string][]*SpvCommand)

	commandStarted := false
	commandWallet := ""
	currentCommand := &SpvCommand{}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "wallets=") {
			if match := reWallets.FindStringSubmatch(line); len(match) == 2 {
				wallets := strings.Split(match[1], ",")
				s.spWallets = wallets
				for _, wallet := range wallets {
					s.services["xr::"+wallet] = true
				}
			}
		} else if strings.HasPrefix(line, "plugins=") {
			if match := rePlugins.FindStringSubmatch(line); len(match) == 2 {
				plugins := strings.Split(match[1], ",")
				for _, plugin := range plugins {
					s.services["xrs::"+plugin] = true
				}
			}
		} else if strings.HasPrefix(line, "host=") {
			if match := reHost.FindStringSubmatch(line); len(match) == 2 {
				if ips, err := net.LookupIP(match[1]); err != nil {
					continue
				} else {
					s.host = match[1]
					s.hostIP = ips[0]
				}
			}
		} else if strings.HasPrefix(line, "port=") {
			if match := rePort.FindStringSubmatch(line); len(match) == 2 {
				s.port, _ = strconv.Atoi(match[1])
			}
		} else if strings.HasPrefix(line, "tls=") {
			if match := reTls.FindStringSubmatch(line); len(match) == 2 {
				if match[1] == "true" || match[1] == "1" {
					s.tls = true
				} else {
					s.tls = false
				}
			}
		} else if strings.HasPrefix(line, "paymentaddress=") {
			if match := rePayment.FindStringSubmatch(line); len(match) == 2 {
				s.paymentAddress = match[1]
			}
		} else if strings.HasPrefix(line, "fee=") && firstFee {
			if match := reFee.FindStringSubmatch(line); len(match) == 2 {
				if fee, err := strconv.ParseFloat(match[1], 32); err == nil {
					s.feedefault = fee
					firstFee = !firstFee
				}
			}
		} else if strings.HasPrefix(line, "[") && !strings.HasPrefix(line, "[Main") {
			// we matched a command block
			commandStarted = true
			// get the wallet name
			s := strings.Split(line, "::")
			if len(s) > 1 {
				commandWallet = strings.Trim(s[0], "[]")
				currentCommand.command = strings.Trim(s[1], "[]")
			}
		} else if commandStarted && line == "" {
			// we're still parsing a command
			commandStarted = false
			commandsToWallets[commandWallet] = append(
				commandsToWallets[commandWallet],
				currentCommand,
			)
		} else if commandStarted {
			if match := reFee.FindStringSubmatch(line); len(match) == 2 {
				if fee, err := strconv.ParseFloat(match[1], 32); err == nil {
					currentCommand.fee = fee
				}
			} else if match := reRequest.FindStringSubmatch(line); len(match) == 2 {
				if requestLimit, err := strconv.ParseInt(match[1], 32, 32); err == nil {
					currentCommand.requestLimit = int(requestLimit)
				}
			} else if match := rePayment.FindStringSubmatch(line); len(match) == 2 {
				currentCommand.paymentAddress = match[1]
			} else if match := reDisabled.FindStringSubmatch(line); len(match) == 2 {
				if disabled, err := strconv.ParseInt(match[1], 32, 32); err == nil {
					if disabled == 0 {
						currentCommand.disabled = false
					} else {
						currentCommand.disabled = true
					}
				}
			}
		}
	}

	if s.port != 0 && strconv.Itoa(s.port) != chaincfg.MainNetParams.DefaultPort &&
		strconv.Itoa(s.port) != chaincfg.TestNet3Params.DefaultPort {
		s.exrCompatible = s.hostIP != nil
	}
	// TLS protocol
	proto := "http://"
	if s.tls {
		proto = "https://"
		s.endpoint = proto + s.host + ":443"
	} else {
		s.endpoint = proto + s.host + ":" + strconv.Itoa(s.port)
	}

	s.servicenode = true
	s.xrouter = true
	s.config = snconf.XRouter.Config

	// extract plugins

	s.plugins = make(map[string]string)
	ss := strings.Split(s.config, "\",\"")
	// assume the first encounter of the separator is the actual separator for plugins
	for i := 1; i < len(ss); i++ {
		// sys_blockchaininfo":"parameters=
		// fee=0.015
		// clientrequestlimit=1000
		// help=Return the SYS coin blockchain info
		// disabled=0
		splitSS := strings.Split(ss[i], "\":\"")

		if len(splitSS) > 0 {
			pluginName := parseString(splitSS[0])
			if strings.HasPrefix(pluginName, "plugins") {
				pluginName = strings.Trim(pluginName, "plugins\":{\"")
			}
			s.plugins[pluginName] = parseString(splitSS[1])
		}
	}

	// spvconfigs     []*SpvConfig
	for k, v := range commandsToWallets {
		conf := &SpvConfig{
			spvwallet: k,
			commands:  make([]*SpvCommand, len(v)),
		}
		for i, command := range v {
			conf.commands[i] = command
		}
		s.spvconfigs = append(s.spvconfigs, conf)
	}

	return &s, nil
}

func (s *ServiceNode) Pubkey() *btcec.PublicKey {
	return s.pubkey
}

func (s *ServiceNode) Endpoint() string {
	return s.endpoint
}

func (s *ServiceNode) EndpointPath(path string) string {
	return s.endpoint + path
}

func (s *ServiceNode) EXRCompatible() bool {
	return s.exrCompatible
}

func (s *ServiceNode) Services() map[string]bool {
	return s.services
}

func (s *ServiceNode) HasService(service string) bool {
	_, ok := s.services[service]
	return ok
}

func (s *ServiceNode) Print() {
	fmt.Printf("Node: %+v\n", s)
	fmt.Println("SPV Configs")
	for _, v := range s.spvconfigs {
		fmt.Printf("For wallet %s got the following commands:\n", v.spvwallet)
		for i, c := range v.commands {
			fmt.Printf("Command %d: %v\n", i, c)
		}
	}
}

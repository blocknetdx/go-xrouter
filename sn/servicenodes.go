// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sn

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
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
	reWallets = regexp.MustCompile("\\s*wallets\\s*=\\s*([a-zA-Z0-9$,_]+)\\s*$")
	rePlugins = regexp.MustCompile("\\s*plugins\\s*=\\s*([a-zA-Z0-9$,_]+)\\s*$")
	reHost    = regexp.MustCompile("\\s*host\\s*=\\s*([a-zA-Z0-9\\.]+)\\s*$")
	rePort    = regexp.MustCompile("\\s*port\\s*=\\s*(\\d+)\\s*$")
	reTls     = regexp.MustCompile("\\s*tls\\s*=\\s*([^\\s]+)\\s*$")
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
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "wallets=") {
			if match := reWallets.FindStringSubmatch(line); len(match) == 2 {
				wallets := strings.Split(match[1], ",")
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

func (s *ServiceNode) HostIP() string {
	return s.hostIP.String()
}

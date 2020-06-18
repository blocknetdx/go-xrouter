// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package sn

import (
	"bufio"
	"bytes"
	"encoding/json"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type ServiceNode struct {
	pubkey        *btcec.PublicKey
	host          net.IP
	port          int
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

func NewServiceNode(pubkey *btcec.PublicKey, config string) *ServiceNode {
	s := ServiceNode{}
	s.pubkey = pubkey
	s.services = make(map[string]bool)

	// Parse config
	var snconf ServiceNodeConfig
	if err := json.Unmarshal([]byte(config), &snconf); err != nil {
		log.Fatal(err)
	}
	confBytes := []byte(snconf.XRouter.Config)
	buf := bytes.NewBuffer(confBytes)
	scanner := bufio.NewScanner(buf)
	reHost := regexp.MustCompile("\\s*host\\s*=\\s*([a-zA-Z0-9\\.]+)\\s*$")
	rePort := regexp.MustCompile("\\s*port\\s*=\\s*(\\d+)\\s*$")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "host=") {
			if match := reHost.FindStringSubmatch(line); len(match) == 2 {
				if ips, err := net.LookupIP(match[1]); err != nil {
					continue
				} else {
					s.host = ips[0]
				}
			}
		} else if strings.HasPrefix(line, "port=") {
			if match := rePort.FindStringSubmatch(line); len(match) == 2 {
				s.port, _ = strconv.Atoi(match[1])
			}
		}
	}

	if s.port != 0 && strconv.Itoa(s.port) != chaincfg.MainNetParams.DefaultPort &&
		strconv.Itoa(s.port) != chaincfg.TestNet3Params.DefaultPort {
		s.exrCompatible = s.host != nil
	}

	return &s
}

func (s *ServiceNode) Pubkey() *btcec.PublicKey {
	return s.pubkey
}

func (s *ServiceNode) Endpoint() string {
	return s.endpoint
}

func (s *ServiceNode) EXRCompatible() bool {
	return s.exrCompatible
}

func (s *ServiceNode) HasService(service string) bool {
	_, ok := s.services[service]
	return ok
}

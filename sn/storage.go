package sn

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
)

type ExportedServiceNode struct {
	Pubkey        string          `json:"pubkey"`
	Host          string          `json:"host"`
	Port          int             `json:"port"`
	TLS           bool            `json:"ttls"`
	Endpoint      string          `json:"endpoint"`
	EXRCompatible bool            `json:"exr_compatible"`
	Services      map[string]bool `json:"services"`
}

type SNodeStorage struct {
	IPs    map[string]struct{}             `json:"ips"`
	SNodes map[string]*ExportedServiceNode `json:"snodes"`
	Count  map[string]int                  `json:"count"`
	sync.Mutex
	Filename string `json:"filename"`
}

func NewSNodeStorage(fname string) *SNodeStorage {
	return &SNodeStorage{
		IPs:      make(map[string]struct{}),
		SNodes:   make(map[string]*ExportedServiceNode),
		Count:    make(map[string]int),
		Filename: fname,
	}
}

func (ssn *SNodeStorage) Add(pubkey string, node *ServiceNode) {
	ip := node.HostIP()
	ssn.Lock()
	defer ssn.Unlock()
	if _, ok := ssn.IPs[ip]; ok {
		return
	}
	ssn.IPs[ip] = struct{}{}
	ssn.SNodes[pubkey] = ssn.convertSNode(node)
}

func (ssn *SNodeStorage) AddCount(pubkey string, node *ServiceNode) {
	ssn.Lock()
	defer ssn.Unlock()
	if _, ok := ssn.SNodes[pubkey]; !ok {
		ssn.Add(pubkey, node)
	}
	if v, ok := ssn.Count[pubkey]; ok {
		ssn.Count[pubkey] = v + 1
	} else {
		ssn.Count[pubkey] = 1
	}
}

func (ssn *SNodeStorage) Remove(pubkey string, node *ServiceNode) {
	ssn.Lock()
	defer ssn.Unlock()
	ip := node.HostIP()
	delete(ssn.IPs, ip)
	delete(ssn.SNodes, pubkey)
	delete(ssn.Count, pubkey)
}

func (ssn *SNodeStorage) List() []*ExportedServiceNode {
	res := make([]*ExportedServiceNode, len(ssn.SNodes))
	i := 0
	for _, v := range ssn.SNodes {
		res[i] = v
		i++
	}
	return res
}

// func (ssn *SNodeStorage) List() []*ServiceNode {
// 	res := make([]*ServiceNode, len(ssn.SNodes))
// 	i := 0
// 	for _, v := range ssn.SNodes {
// 		res[i] = ssn.convertSNode(v)
// 		i++
// 	}
// 	return res
// }

func (ssn *SNodeStorage) Store() {
	file, _ := json.MarshalIndent(ssn, "", " ")
	fmt.Println(file)
	_ = ioutil.WriteFile(ssn.Filename, file, 0644)
}

func (ssn *SNodeStorage) Load() {
	jsonFile, err := os.Open(ssn.Filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal(byteValue, ssn)
}

func (ssn *SNodeStorage) convertSNode(node *ServiceNode) *ExportedServiceNode {
	return &ExportedServiceNode{
		Pubkey:        hex.EncodeToString(node.Pubkey().SerializeCompressed()),
		Host:          node.host,
		Port:          node.port,
		TLS:           node.tls,
		Endpoint:      node.endpoint,
		EXRCompatible: node.exrCompatible,
		Services:      node.services,
	}
}

package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/blocknetdx/go-xrouter/sn"
)

type SNodeStorage struct {
	ips    map[string]struct{}
	snodes map[string]*sn.ServiceNode
	count  map[string]int
	sync.Mutex
	filename string
}

func NewSNodeStorage(fname string) *SNodeStorage {
	return &SNodeStorage{
		ips:      make(map[string]struct{}),
		snodes:   make(map[string]*sn.ServiceNode),
		filename: fname,
	}
}

func (ssn *SNodeStorage) Add(pubkey string, node *sn.ServiceNode) {
	ip := node.HostIP()
	ssn.Lock()
	defer ssn.Unlock()
	if _, ok := ssn.ips[ip]; ok {
		return
	}
	ssn.ips[ip] = struct{}{}
	ssn.snodes[pubkey] = node
}

func (ssn *SNodeStorage) AddCount(pubkey string, node *sn.ServiceNode) {
	ssn.Lock()
	defer ssn.Unlock()
	if _, ok := ssn.snodes[pubkey]; !ok {
		ssn.Add(pubkey, node)
	}
	if v, ok := ssn.count[pubkey]; ok {
		ssn.count[pubkey] = v + 1
	} else {
		ssn.count[pubkey] = 1
	}
}

func (ssn *SNodeStorage) Remove(pubkey string, node *sn.ServiceNode) {
	ssn.Lock()
	defer ssn.Unlock()
	ip := node.HostIP()
	delete(ssn.ips, ip)
	delete(ssn.snodes, pubkey)
	delete(ssn.count, pubkey)
}

func (ssn *SNodeStorage) List() []*sn.ServiceNode {
	res := make([]*sn.ServiceNode, len(ssn.snodes))
	i := 0
	for _, v := range ssn.snodes {
		res[i] = v
		i++
	}
	return res
}

func (ssn *SNodeStorage) Store() {
	file, _ := json.MarshalIndent(ssn.snodes, "", " ")
	fmt.Println(file)
	_ = ioutil.WriteFile(ssn.filename, file, 0644)
}

func (ssn *SNodeStorage) Load() {

}

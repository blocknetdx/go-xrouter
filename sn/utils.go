package sn

import (
	"net"
)

func ConvertToExport(node *ServiceNode) *ExportedServiceNode {
	sen := &ExportedServiceNode{
		Pubkey:        node.pubkey,
		Host:          node.host,
		Port:          node.port,
		TLS:           node.tls,
		Endpoint:      node.endpoint,
		EXRCompatible: node.exrCompatible,
		Services:      node.services,
	}
	return sen
}

func ConvertToExportMultiple(nodes []*ServiceNode) []ExportedServiceNode {
	sens := make([]ExportedServiceNode, len(nodes))
	for i, v := range nodes {
		sens[i] = *ConvertToExport(v)
	}
	return sens
}

func ConvertToProper(node *ExportedServiceNode) *ServiceNode {
	sn := &ServiceNode{
		pubkey:        node.Pubkey,
		host:          node.Host,
		port:          node.Port,
		hostIP:        net.ParseIP(node.Host).To4(),
		tls:           node.TLS,
		endpoint:      node.Endpoint,
		exrCompatible: node.EXRCompatible,
		services:      node.Services,
	}
	return sn
}

func ConvertToProperMultiple(nodes []*ExportedServiceNode) []*ServiceNode {
	sns := make([]*ServiceNode, len(nodes))
	for i, v := range nodes {
		sns[i] = ConvertToProper(v)
	}
	return sns
}

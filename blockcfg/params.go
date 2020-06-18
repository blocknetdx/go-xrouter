// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package blockcfg

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

var MainnetParams = chaincfg.Params{
	Name:        "mainnet",
	Net:         wire.MainNet,
	DefaultPort: "41412",
	DNSSeeds: []chaincfg.DNSSeed{
		{"seed1.blocknet.co", false},
		{"seed2.blocknet.co", false},
		{"seed3.blocknet.co", false},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "block",

	// Address encoding magics
	PubKeyHashAddrID:        0x1a, // starts with B
	ScriptHashAddrID:        0x1c, // starts with C
	PrivateKeyID:            0x9a, // starts with 6 (uncompressed) or P (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0a, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub
	HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,
}

var TestnetParams = chaincfg.Params{
	Name:        "testnet",
	Net:         wire.TestNet3,
	DefaultPort: "41474",
	DNSSeeds: []chaincfg.DNSSeed{
		{"3.16.3.126", false},
		{"18.224.130.185", false},
		{"18.213.44.27", false},
		{"34.196.102.239", false},
	},

	// Mempool parameters
	RelayNonStdTxs: false,

	// Human-readable part for Bech32 encoded segwit addresses, as defined in
	// BIP 173.
	Bech32HRPSegwit: "tblock",

	// Address encoding magics
	PubKeyHashAddrID:        0x8b, // starts with x or y
	ScriptHashAddrID:        0x13, // starts with 8
	PrivateKeyID:            0xef, // starts with 6 (uncompressed) or P (compressed)
	WitnessPubKeyHashAddrID: 0x06, // starts with p2
	WitnessScriptHashAddrID: 0x0a, // starts with 7Xh

	// BIP32 hierarchical deterministic extended key magics
	HDPublicKeyID:  [4]byte{0x3a, 0x80, 0x61, 0xa0},
	HDPrivateKeyID: [4]byte{0x3a, 0x80, 0x58, 0x37},

	// BIP44 coin type used in the hierarchical deterministic path for
	// address generation.
	HDCoinType: 0,
}

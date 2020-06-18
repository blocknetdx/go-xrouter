// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"github.com/blocknetdx/go-xrouter/blockcfg"
	"github.com/blocknetdx/go-xrouter/xrouter"
)

func main() {
	client, err := xrouter.NewClient(blockcfg.TestnetParams)
	if err != nil {
		println(err.Error())
		return
	}
	client.Start()
	client.WaitForShutdown()
	println("Done")
}

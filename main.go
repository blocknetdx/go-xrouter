// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/blocknetdx/go-xrouter/blockcfg"
	"github.com/blocknetdx/go-xrouter/xrouter"
)

func main() {
	log.SetOutput(os.Stdout)

	config := blockcfg.MainnetParams
	// Manually set seed node (via ip or dns)
	//config.DNSSeeds = []chaincfg.DNSSeed{
	//	{"seed1.blocknet.co", false}, // optional direct connect to trusted node
	//}
	// Instantiate the xrouter client
	client, err := xrouter.NewClient(config)
	if err != nil {
		log.Println(err.Error())
		return
	}
	// Start xrouter (this will begin querying the network)
	client.Start()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defer shutdown(client)

	// Wait for xrouter to be ready
	if ready, err := client.WaitForXRouter(ctx); err != nil || !ready {
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		log.Println("XRouter failed to connect and obtain service nodes", errStr)
		return
	}
	log.Printf("XRouter is ready")

	// List all network services
	//for _, service := range client.ListNetworkServices() {
	//	log.Printf(service)
	//}

	ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	defer cancel2()
	queryCount := 1
	if err := client.WaitForServices(ctx2, []string{"xrs::CCSinglePrice", "xr::BTC"}, queryCount); err != nil {
		log.Printf("error: %v", err)
		return
	}

	{
		// Query the price oracle to obtain Bitcoin's price in USD
		var params []interface{}
		params = append(params, "BTC", "USD")
		if reply, flag, err := client.CallService("xrs::CCSinglePrice", params, queryCount); err != nil {
			log.Printf("error: %v", err)
			return
		} else {
			if reply == nil {
				log.Printf("No replies found. %v\n", flag)
			} else {
				log.Printf("Result from %v: %v. %v", hex.EncodeToString(reply.Pubkey), string(reply.Reply), flag)

			}
		}
	}

	{
		// Query the BTC oracle to obtain the chain height
		if reply, flag, err := client.DecodeTransaction("xr::BTC", "0200000002bf7eb59492ac17790260c4d973e05ac01d2a6cfdb15ea1f6a8a79523d12795b3000000006a473044022053eb941aa0d653cc42cfe0a6c9736027083584c81084dc74c0498f158e5403150220438d291ebfe2496cc1cd3a7ca1886ac4dfecb28aa4b64bf1373cc682d22c62220121024e73b4b876b88221355eaefcfee427272f29a01d7f287680dc7ea759605fd233ffffffffbf7eb59492ac17790260c4d973e05ac01d2a6cfdb15ea1f6a8a79523d12795b3010000006a473044022079cebcb4d20a58b7c3b2afbbf8e8871b92cc46f498b4ee99be667c5e474f071002205949030a7972c00e18ea50b5f218a79231a0f32cec6141fcc0c105adc55be6450121024e73b4b876b88221355eaefcfee427272f29a01d7f287680dc7ea759605fd233ffffffff01827d2b00000000001976a9144753777940c90845fb74ca889605f3b0289a817f88ac00000000", 1); err != nil {
			log.Printf("error: %v", err)
			return
		} else {
			if reply == nil {
				log.Printf("No replies found. %v\n", flag)
			} else {
				log.Printf("Result from %v: %v. %v", hex.EncodeToString(reply.Pubkey), string(reply.Reply), flag)

			}
		}
	}
}

func shutdown(client *xrouter.Client) {
	if err := client.Stop(); err != nil {
		fmt.Printf("error shutdown: %v", err)
	}
}

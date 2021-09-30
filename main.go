// Copyright (c) 2020 The Blocknet developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
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
	// for _, service := range client.ListNetworkServices() {
	// 	log.Printf(service)
	// }

	// ctx2, cancel2 := context.WithTimeout(ctx, 5*time.Second)
	// defer cancel2()
	queryCount := 7
	// if err := client.WaitForServices(ctx2, []string{"xrs::CCSinglePrice", "xr::BTC"}, queryCount); err != nil {
	// 	log.Printf("error: %v", err)
	// 	return
	// }

	// {
	// 	// Query the price oracle to obtain Bitcoin's price in USD
	// 	var params []interface{}
	// 	params = append(params, "BTC", "USD")
	// 	if reply, err := client.CallService("xrs::CCSinglePrice", params, queryCount); err != nil {
	// 		log.Printf("error: %v", err)
	// 		return
	// 	} else {
	// 		if len(reply.Divergent) == 0 && reply.MostCommonReplyCount == 0 {
	// 			log.Printf("No replies found. %v\n", reply.Message)
	// 		} else if len(reply.Divergent) != 0 && reply.MostCommonReplyCount == 0 {
	// 			log.Printf("No most common replies, but got %v divergent replies\n", reply.DivergentReplies)
	// 		} else {
	// 			log.Printf(
	// 				"Result from %v: %v with %v divergent replies and majority strength %.2f%%.\n",
	// 				hex.EncodeToString(reply.MostCommonReply.Pubkey),
	// 				string(reply.MostCommonReply.Reply),
	// 				reply.DivergentReplies,
	// 				reply.MajorityStrength,
	// 			)
	// 		}
	// 		if len(reply.Divergent) != 0 {
	// 			log.Println("Diveregent replies are provided below.")
	// 			for _, v := range reply.Divergent {
	// 				log.Printf(
	// 					"Divergent result from %v: %v with %v reply counts.",
	// 					hex.EncodeToString(v.Reply.Pubkey),
	// 					string(v.Reply.Reply),
	// 					v.ResponseCount,
	// 				)
	// 			}
	// 		}
	// 		log.Println("The full response is provided below.")
	// 		s, _ := json.MarshalIndent(reply, "", "\t")
	// 		log.Println(string(s))
	// 	}
	// }

	{
		// Query the BTC oracle to obtain the chain height
		if reply, err := client.GetBlockCount("xr::LTC", queryCount); err != nil {
			log.Printf("error: %v", err)
			return
		} else {
			if len(reply.Consensus.DivergentReplies) == 0 && reply.Consensus.MostCommonReplyCount == 0 {
				log.Printf("No replies found. %v\n", reply.QueryCount)
			} else if len(reply.Consensus.DivergentReplies) != 0 && reply.Consensus.MostCommonReplyCount == 0 {
				log.Printf("No most common replies, but got %v divergent replies\n", reply.Consensus.DivergentReplies)
			} else {
				log.Printf(
					"Result %v with %v divergent replies and majority strength %s.\n",
					// hex.EncodeToString(reply.MostCommonReply.Pubkey),
					string(reply.Consensus.MostCommonReply.Reply),
					reply.Consensus.DivergentReplyCount,
					reply.Consensus.MajorityStrength,
				)
			}
			if len(reply.Consensus.DivergentReplies) != 0 {
				log.Println("Diveregent replies are provided below.")
				for _, v := range reply.Consensus.DivergentReplies {
					log.Printf(
						"Divergent result %v with %v reply counts.",
						// hex.EncodeToString(v.Reply.),
						string(v.Reply.Reply),
						v.Count,
					)
				}
			}
			log.Println("The full response is provided below.")
			s, _ := json.MarshalIndent(reply, "", "\t")
			log.Println(string(s))
		}
	}

}

func shutdown(client *xrouter.Client) {
	if err := client.Stop(); err != nil {
		fmt.Printf("error shutdown: %v", err)
	}
}

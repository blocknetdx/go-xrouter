go-xrouter Library
=====================================

The go-xrouter library allows go developers and ethereum developers to query blockchain data and oracles via Blocknet's XRouter interoperability protocol. Get started with XRouter without virtual machines or smart contracts in a few lines of code. The library queries the Blocknet network, obtains a list of service nodes (service providers), and submits requests to those service providers' oracles and microservices.

https://blocknet.co

[Website](https://blocknet.co) | [API](https://api.blocknet.co) | [Documentation](https://docs.blocknet.co) | [Discord](https://discord.gg/2e6s7H8)
-------------|-------------|-------------|-------------

GETTING STARTED
---------------

Go 1.14+ is required.

### Step 1. Pull the library into your go workspace

```
go get https://github.com/blocknetdx/go-xrouter
```

### Step 2. Create go application "main.go"

main.go

```go
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/blocknetdx/go-xrouter/blockcfg"
	"github.com/blocknetdx/go-xrouter/xrouter"
	"log"
	"os"
	"time"
)

func main() {
	log.SetOutput(os.Stdout)
    
    // Instantiate the xrouter client
    client, err := xrouter.NewClient(blockcfg.MainnetParams)
    if err != nil {
        log.Println(err.Error())
        return
    }
    // Start xrouter (this will begin querying the network)
    client.Start()

    ctx, cancel := context.WithTimeout(context.Background(), 30 * time.Second)
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

    ctx2, cancel2 := context.WithTimeout(ctx, 5 * time.Second)
    defer cancel2()
    queryCount := 1
    if err := client.WaitForServices(ctx2, []string{"xrs::CCSinglePrice","xr::BTC"}, queryCount); err != nil {
        log.Printf("error: %v", err)
        return
    }

    {
        // Query the price oracle to obtain Bitcoin's price in USD
        var params []interface{}
        params = append(params, "BTC", "USD")
        if reply, err := client.CallService("xrs::CCSinglePrice", params, queryCount); err != nil {
            log.Printf("error: %v", err)
            return
        } else {
            log.Printf("result from %v: %v", hex.EncodeToString(reply.Pubkey), string(reply.Reply))
        }
    }

    {
        // Query the BTC oracle to obtain the chain height
        if reply, err := client.GetBlockCount("xr::BTC", queryCount); err != nil {
            log.Printf("error: %v", err)
            return
        } else {
            log.Printf("result from %v: %v", hex.EncodeToString(reply.Pubkey), string(reply.Reply))
        }
    }
}

func shutdown(client *xrouter.Client) {
	if err := client.Stop(); err != nil {
		fmt.Printf("error shutdown: %v", err)
	}
}
```

### Step 3. Build and Run

```go
go run main.go
```

License
-------

ISC License

Copyright (c) 2020 The Blocknet developers

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
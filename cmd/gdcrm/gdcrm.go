package main

import (
	"fmt"
	"os"
	"time"

	"github.com/fusion/go-fusion/crypto"
	"github.com/fusion/go-fusion/p2p"
	"github.com/fusion/go-fusion/p2p/discover"
	"github.com/fusion/go-fusion/p2p/nat"
	"gopkg.in/urfave/cli.v1"
	"github.com/fusion/go-fusion/p2p/layer2"
	rpcdcrm "github.com/fusion/go-fusion/rpc/dcrm"
	"github.com/fusion/go-fusion/crypto/dcrm"
	//"github.com/fusion/go-fusion/crypto/dcrm/dev"
)

func main() {

	time.Sleep(time.Duration(20) * time.Second)
	rpcdcrm.RpcInit(rpcport)
	dcrm.Start()

	select {} // note for server, or for client
}

//========================= init ========================
var (
	//args
	rpcport      int
	port      int
	bootnodes string
	keyfile   string
)

var count int = 0

func init() {
	verbosity := 4//int(log.LvlInfo)
	app := cli.NewApp()
	app.Usage = "Layer2 Init"
	app.Action = startP2pNode
	app.Flags = []cli.Flag{
		cli.IntFlag{Name: "rpcport", Value: 9010, Usage: "listen port", Destination: &rpcport},
		cli.IntFlag{Name: "port", Value: 0, Usage: "listen port", Destination: &port},
		cli.StringFlag{Name: "bootnodes", Value: "", Usage: "boot node", Destination: &bootnodes},
		cli.StringFlag{Name: "nodekey", Value: "", Usage: "private key filename", Destination: &keyfile},
		cli.IntFlag{Name: "verbosity", Value: 4, Usage: "log verbosity (0-9)", Destination: &verbosity},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func startP2pNode(c *cli.Context) error {
	go func() error {
		switch {
		}
		nodeKey, errkey := crypto.LoadECDSA(keyfile)
		if errkey != nil {
		    nodeKey, _ = crypto.GenerateKey()
		    crypto.SaveECDSA(keyfile, nodeKey)
		    var kfd *os.File
		    kfd, _ = os.OpenFile(keyfile, os.O_WRONLY|os.O_APPEND, 0600)
		    kfd.WriteString(fmt.Sprintf("\nenode://%v\n", discover.PubkeyID(&nodeKey.PublicKey)))
		    kfd.Close()
		}
		//fmt.Printf("nodekey: %+v\n", nodeKey)

		dcrm := layer2.DcrmNew(nil)
		nodeserv := p2p.Server{
			Config: p2p.Config{
				MaxPeers:        100,
				MaxPendingPeers: 100,
				NoDiscovery:     false,
				PrivateKey:      nodeKey,
				Name:            "p2p layer2",
				ListenAddr:      fmt.Sprintf(":%d", port),
				Protocols:       dcrm.Protocols(),
				NAT:             nat.Any(),
				//Logger:     logger,
			},
		}

		bootNodes, err := discover.ParseNode(bootnodes)
		if err != nil {
			return err
		}
		fmt.Printf("==== startP2pNode() ====, bootnodes = %v\n", bootNodes)
		nodeserv.Config.BootstrapNodes = []*discover.Node{bootNodes}

		if err := nodeserv.Start(); err != nil {
			return err
		}

		//fmt.Printf("\nNodeInfo: %+v\n", nodeserv.NodeInfo())
		fmt.Println("\n=================== P2P Service Start! ===================\n")
		select {}
	}()
	return nil
}


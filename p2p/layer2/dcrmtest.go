package layer2

import (
	"fmt"
	"time"
	//"github.com/ethereum/go-ethereum/p2p/layer2"
)

//call define
func call(msg interface{}) <-chan string {
	fmt.Printf("\ndcrm call: msg = %v\n", msg)
	ch := make(chan string, 800)
	return ch
}

func dcrmcall(msg interface{}) <-chan string {
	ch := make(chan string, 800)
	fmt.Printf("\ndcrm dcrmcall: msg=%v\n", msg)
	dcrmcallMsg := fmt.Sprintf("%v dcrmcall", msg)
	DcrmProtocol_broadcastInGroupOthers(dcrmcallMsg) // without self
	ch <- msg.(string)
	return ch
}

func dcrmcallret(msg interface{}) {
	fmt.Printf("dcrm dcrmcallret: msg=%v\n", msg)
}

func main() {
	fmt.Printf("\n\nDCRM P2P test ...\n\n")
	DcrmProtocol_registerRecvCallback(call) // <- Dcrmrotocol_broadcastToGroup(dcrmcallMsg)
	DcrmProtocol_registerMsgRecvCallback(dcrmcall)
	DcrmProtocol_registerMsgRetCallback(dcrmcallret)

	time.Sleep(time.Duration(10) * time.Second)

	//select {} // note for server, or for client

	var num int = 0
	for {
		fmt.Printf("\nSendToDcrmGroup ...\n")
		num += 1
		msg := fmt.Sprintf("%+v test SendToDcrmGroup ...", num)
		DcrmProtocol_sendToGroupOneNode(msg)// -> Handle: DcrmProtocol_registerCallback(call)
					           // -> *msg Handle: DcrmProtocol_registerMsgRecvCallback(dcrmcall)
					           //    DcrmProtocol_registerMsgRetCallback(dcrmcallret) <- DcrmProtocol_registerMsgRecvCallback(dcrmcall)
		time.Sleep(time.Duration(2) * time.Second)
	}
	select {}
}


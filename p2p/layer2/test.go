package layer2

import (
	"fmt"
	"time"
)

//call define
func bcall(msg interface{}, fromID string) {
	fmt.Printf("\nBroadcast call: msg = %v\n", msg)
}

func CC_startTest() {
	fmt.Printf("\n\nBroadcast test ...\n\n")
	RegisterCallback(bcall)

	time.Sleep(time.Duration(10) * time.Second)

	//select {} // note for client, or for server

	var num int = 0
	for {
		fmt.Printf("\nBroadcast ...\n")
		num += 1
		msgtest := fmt.Sprintf("%+v test Broadcast ...", num)
		Broadcast(msgtest)
		time.Sleep(time.Duration(3) * time.Second)
	}

	select {}
}

package main

import (
	"fmt"
	"github.com/BobBurns/hackicmp6/hi6"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("must specify interface!")
		os.Exit(-1)
	}
	t := hi6.ICMP6{
		Iface:        os.Args[1],
		PreferGlobal: false,
		DstIP:        "ff02::2",
		SrcIP:        "", // should be inferred from interface
		SrcMAC:       "", // should be inferred from interface
		DstMAC:       "", // should be inferred from multicast
		Type:         hi6.ICMPTypeMulticastListenerQuery,
		Code:         0,
		MLD_MaxDelay: uint16(10),
		MLD_Addr:     "fe80::3",
	}

	err := t.BuildICMPPacket()
	if err != nil {
		panic(err)
	}
	for {
		fmt.Printf(".")
		err = t.Send()
		time.Sleep(time.Duration(30 * time.Second))
	}

}

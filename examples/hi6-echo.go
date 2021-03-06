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
		Iface: os.Args[1],
		DstIP: "2001:db8:103::1",
		// optional. Use to spoof source address
		SrcIP: "2001:db8:103:b::1",
		// optional. Use to spoof source address
		SrcMAC: "c0:8c:60:de:ad:bf",
		// required
		DstMAC: "88:f7:c7:de:ad:bf",
		Type:   hi6.ICMPTypeEchoRequest,
		Code:   0,
		// payload data
		Data: []byte{
			'a',
			'b',
			'c',
			'd',
			'e',
			'e',
			'f',
			'g',
			'h',
			'i',
			'j',
			'k',
			'l',
			'm',
			'n',
			'o',
		},
	}
	t.DataLen = len(t.Data)

	i := 0
	for {
		t.ICMP6_seq = uint16(i)
		i++
		err := t.BuildICMPPacket()
		if err != nil {
			fmt.Println("errors found...")
			fmt.Println(err)
			fmt.Println("exiting.")
			os.Exit(-1)
		}
		for {
			fmt.Printf(".")
			err = t.Send()
			if err != nil {
				fmt.Println(err)
				os.Exit(-1)
			}
			time.Sleep(time.Duration(1 * time.Second))
		}
	}

}

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
			'a', //0x00,
			'b', //0x20,
			'c', //0x00,
			'd', //0x00,
			'e', //0x00,
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
			panic(err)
		}
		for {
			err = t.Send()
			time.Sleep(time.Duration(1 * time.Second))
		}
	}

}

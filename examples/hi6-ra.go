// Router Advertisement
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
		Iface:              os.Args[1],
		PreferGlobal:       false,
		DstIP:              "ff02::1",
		// change the address to suit your need
		SrcIP:              "fe80::1234",
		SrcMAC:             "10:0b:a9:aa:aa:aa",
		DstMAC:             "33:33:00:00:00:01",
		Type:               hi6.ICMPTypeRouterAdvertisement,
		Code:               0,
		RA_Flags:           hi6.RA_FLAG_OTHER | hi6.RA_FLAG_PREF_HIGH,
		RA_Curhoplimit:     64,
		RA_Router_lifetime: uint16(9000),
		RA_Reachable:       uint32(0),
		RA_Retransmit:      uint32(0),
	}
	op1 := hi6.Option{
		Type: hi6.OPT_SOURCE_LINKADDR,
		// change this
		Addr: "10:0b:a9:bb:bb:bb",
	}
	t.AddOption(op1)

	op2 := hi6.Option{
		Type:          hi6.OPT_PREFIX_INFORMATION,
		PI_Prefix_Len: 64,
		PI_Flags:      hi6.OPT_FLAG_ONLINK | hi6.OPT_FLAG_AUTO,
		PI_Valid_Time: uint32(2500000),
		PI_Pref_Time:  uint32(600000),
		Addr:          "2001:db8:3:f::",
	}
	t.AddOption(op2)
	op3 := hi6.Option{
		Type:          hi6.OPT_RDNS,
		RDNS_Lifetime: uint32(9000),
		RDNS_Server1:  "2001:db8:5:1::1",
		RDNS_Server2:  "2001:db8:5:1::2",
	}
	t.AddOption(op3)

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

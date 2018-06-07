// Router Solicitation with Option
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
		PreferGlobal:             true,
		DstIP:              "ff02::1",
		SrcIP:              "",
		SrcMAC:             "",
		DstMAC:		"33:33:00:00:00:01",
		Type:               hi6.ICMPTypeRedirect,
		Code:               0,
		TargetAddr:		"fe80::bbbb:aaaa",
		DestAddr:		"ff02::1",
	}
	op1 := hi6.Option{
		Type: hi6.OPT_SOURCE_LINKADDR,
		Addr: "10:0b:a9:cc:cc:cc",
	}
	t.AddOption(op1)

	op2 := hi6.Option{
		Type:          hi6.OPT_PREFIX_INFORMATION,
		PI_Prefix_Len: 64,
		PI_Flags:      hi6.OPT_FLAG_ONLINK | hi6.OPT_FLAG_AUTO,
		PI_Valid_Time: uint32(2592000),
		PI_Pref_Time:  uint32(604800),
		Addr:          "2001:db8:203:3::",
	}
	t.AddOption(op2)

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

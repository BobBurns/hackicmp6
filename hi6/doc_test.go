package hi6

func Example() {

	t := hi6.ICMP6{
		Iface:        "en0",
		DstIP:        "ff02::1",
		PreferGlobal: false,
		SrcIP:        "", // will find interface link local IP6 address
		SrcMAC:       "", // will find interface MAC
		DstMAC:       "33:33:00:00:00:01",
		Type:         hi6.ICMPTypeNeighborAdvertisement,
		Code:         0,
		NA_Flags:     hi6.NA_FLAG_OVERRIDE,
		TargetAddr:   "fe80::123",
	}

	err := t.BuildICMPPacket()
	if err != nil {
		panic(err)
	}
	for {
		err = t.Send()
		time.Sleep(time.Duration(1 * time.Second))
	}

}

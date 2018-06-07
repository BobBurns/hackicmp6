// HackICMP6 is a simple package to use to build and send ICMP6 packets from  Ethernet, IPv6 and ICMP6 Headers with Options. Only supported on Linux
//
// For reference to ICMP6 see RFC 3542
package hi6

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/songgao/ether"
	"github.com/songgao/packets/ethernet"
	"net"
	"strings"
	"syscall"
)

// Various header lengths
const (
	EtherLen      = 14
	IPHeaderLen   = 40
	ICMPHeaderLen = 8
)

// ICMP6 Option Header Types
const (
	OPT_SOURCE_LINKADDR    = 1
	OPT_TARGET_LINKADDR    = 2
	OPT_PREFIX_INFORMATION = 3
	OPT_REDIRECT_HEADER    = 4
	OPT_MTU                = 5
	OPT_RDNS               = 25
)

// ICMP6 Option Header Prefix Info Flags
const (
	OPT_FLAG_ONLINK = 0x80
	OPT_FLAG_AUTO   = 0x40
	OPT_FLAG_ROUTER = 0x20
)

// ICMP6 Router Advertisement Flags
const (
	RA_FLAG_MANAGED   = 0x80
	RA_FLAG_OTHER     = 0x40
	RA_FLAG_HOME      = 0x20
	RA_FLAG_PREF_HIGH = 0x08
	RA_FLAG_PREF_MED  = 0x00
	RA_FLAG_PREF_LOW  = 0x18
	RA_FLAG_PROXY     = 0x04
)

// ICMP6 Neighbor Advertisement Flags
const (
	NA_FLAG_ROUTER    = 0x80
	NA_FLAG_SOLICITED = 0x40
	NA_FLAG_OVERRIDE  = 0x20
)

// ICMP6 Router Renumbering Flags
const (
	RR_FLAGS_TEST       = 0x80
	RR_FLAGS_REQRESULT  = 0x40
	RR_FLAGS_FORCEAPPLY = 0x20
	RR_FLAGS_SPECSITE   = 0x10
	RR_FLAGS_PREVDONE   = 0x08
)

// ICMP6 Router Renumbering PCO Codes
const (
	RR_PCO_ADD       = 1
	RR_PCO_CHANGE    = 2
	RR_PCO_SETGLOBAL = 3
)

// ICMP6 Router Renumbering PCO Use RA Flags
const (
	RR_RAFLAGS_ONLINK = 0x20
	RR_RAFLAGS_AUTO   = 0x40
)

// ICMP6 Router Renumbering PCO Use Flags
const (
	RR_PCOUSE_FLAGS_DECRVLTIME = 0x80
	RR_PCOUSE_FLAGS_DECRPLTIME = 0x40
)

// ICMP6 struct is where you fill in Ethernet, IP6, ICMP6
// Parameters to build the frame
type ICMP6 struct {
	// Interface to send frame on
	Iface string

	// Source IP6 Address
	// If empty, the program will attempt to assign one
	// from the interface. If PreferGlobal is true, will
	// use the global address, else the link local address
	SrcIP string

	// Destination IP6 Address. Must be specified
	DstIP string

	// Source MAC Address. If empty the program will try and get the
	// interface MAC address
	SrcMAC string

	// Destination MAC address. If empty and IP6 address
	// is Multicast, will use Multicast MAC address, else
	// will throw error
	DstMAC string

	// Set to true to have the program use the global address
	// of the interface
	PreferGlobal bool

	// ICMP Type
	Type ICMPType

	// ICMP Code
	Code int

	// ICMP Data. Should be empty if builing Packet from Type
	ICMPData [4]byte

	// ICMP Payload. To use for building raw ICMP Packets
	Data []byte

	// ICMP Payload length
	DataLen int

	// Set to true to use raw ICMP Data
	UseICMPData bool

	// Data Field for ICMP6 Parameter Problem
	ICMP6_pptr uint32 /* parameter prob */

	// Data Field for ICMP6 Packet Too Big
	ICMP6_mtu uint32

	// Data Field for ICMP6 Echo Request/Reply ID
	ICMP6_id uint16

	// Data Field for ICMP6 Echo Request/Reply Sequence
	ICMP6_seq uint16

	// Data Field for ICMP6 Echo Request/Reply Sequence
	ICMP6_maxdelay uint16 /* mcast group membership */

	// Target IP6 Address. Use for Neighbor Advertisement
	// and Neighbor Solicitation
	TargetAddr string

	// Destination IP6 Address for Router Redirect
	DestAddr string

	// Router Advertisement Flags
	RA_Flags int

	// Router Advertisement Current Hop Limit
	RA_Curhoplimit int

	// Router Advertisement Router Lifetime
	RA_Router_lifetime uint16

	// Router Advertisement Reachable Time
	RA_Reachable uint32

	// Router Advertisement Retransmit Time
	RA_Retransmit uint32

	// Neighbor Advertisement Flags
	NA_Flags int

	// Multicast Listener Discovery Max Delay
	MLD_MaxDelay uint16

	// Multicast Listener Discovery IP6 Address
	MLD_Addr string

	// Router Renumbering Sequence Number
	RR_Seqnum int

	// Router Renumbering Segment Number
	RR_Segnum int

	// Router Renumbering Flags
	RR_Flags int

	// Router Renumbering Max Delay
	RR_MaxDelay int

	// Router Renumbering PCO Match Header
	RR_PCOMatch PCOMatch

	// Router Renumbering Array of PCO Use Headers
	RR_PCOUse []PCOUse

	// ICMP6 Options (ie Source LinkAddr, Target LinkAddr,
	// Prefix Info, MTU)
	Options []Option

	// internal
	frame ethernet.Frame
}

// Option Struct to add options to a few ICMP6 Packets
type Option struct {
	// Option Type
	Type int

	// IP6 Address for Source/Target LinkAddrss
	Addr string

	// Option Prefix Info
	RA_Reachable  uint32
	RA_Retransmit uint32
	PI_Prefix_Len int
	PI_Flags      byte
	PI_Valid_Time uint32
	PI_Pref_Time  uint32
	MTU           uint32

	// Recursive DNS Servers
	RDNS_Lifetime uint32

	// Only supporting 2
	RDNS_Server1 string
	RDNS_Server2 string
}

// Router Renumbering PCO Match Header
type PCOMatch struct {
	Code     int
	Len      int
	Ordinal  int
	MatchLen int
	MinLen   int
	MaxLen   int
	Prefix   string
}

// Router Renumbering PCO Use Header
type PCOUse struct {
	UseLen           int
	KeepLen          int
	RA_Mask          int
	RA_Flags         int
	ValidLifetime    int
	PreferedLifetime int
	Flags            int
	Prefix           string
}

// Convenience function to add Options to ICMP6 struct
func (t *ICMP6) AddOption(o Option) {
	t.Options = append(t.Options, o)
}

// Convenience function to add PCOUse to ICMP6 struct
func (t *ICMP6) AddPCOUse(pu PCOUse) {
	t.RR_PCOUse = append(t.RR_PCOUse, pu)
}

// this will be called from BuildICMPPacket
func (t *ICMP6) verifyAddr() error {

	vErr := errors.New("Failed Verify ICMP6!")

	iface, err := net.InterfaceByName(t.Iface)

	if err != nil {
		fmt.Println(err)
		return vErr
	}
	if t.Iface == "" {
		fmt.Println("Must have interface")
		return vErr
	}

	// Destination MAC
	if t.DstMAC == "" {
		if strings.HasPrefix(t.DstIP, "ff") || strings.HasPrefix(t.DstIP, "FF") {
			tmpIP := net.ParseIP(t.DstIP)
			t.DstMAC = fmt.Sprintf("33:33:%02X:%02X:%02X:%02X", tmpIP[12], tmpIP[13], tmpIP[14], tmpIP[15])
			//debug
			//fmt.Println("dstMAC", t.DstMAC)
		} else {
			fmt.Println("Must have Destination MAC Address")
			return vErr
		}
	} else if _, err := net.ParseMAC(t.DstMAC); err != nil {
		fmt.Println(err)
		return vErr
	}

	// Source MAC
	if t.SrcMAC == "" {
		t.SrcMAC = iface.HardwareAddr.String()
		if t.SrcMAC == "" {
			t.SrcMAC = "00:00:00:00:00:00"
		}
	} else if _, err := net.ParseMAC(t.SrcMAC); err != nil {
		fmt.Println(err)
		return vErr
	}

	// Verify IPs

	// Source IP Addr
	if t.SrcIP == "" {
		// get interface addresses
		iAddr, err := iface.Addrs()
		if err != nil {
			fmt.Println(err)
			return vErr
		}
		// debug
		//fmt.Println("Flags: ", iface.Flags.String())

		for _, a := range iAddr {
			// handle prefix len on linux
			ad := strings.Split(a.String(), "/")
			// debug
			//fmt.Println(ad)

			// loopback?
			if (iface.Flags&net.FlagLoopback) > 0 && strings.Contains(ad[0], ":") {
				t.SrcIP = ad[0]
				break
			} else if strings.HasPrefix(ad[0], "fe80") && t.PreferGlobal == false {
				t.SrcIP = ad[0]
				break
			} else if strings.Contains(ad[0], ":") && t.PreferGlobal == true {
				t.SrcIP = ad[0]
				break
			}
		}
		if t.SrcIP == "" {
			fmt.Println("Could not find Source IP")
			return vErr
		}

	} else if net.ParseIP(t.SrcIP) == nil {
		fmt.Println("Not a Valid Source IP")
		return vErr
	}

	// Destination IP Addr
	if net.ParseIP(t.DstIP) == nil {
		fmt.Println("Not a Valid Destination IP")
		return vErr
	}

	//debug
	//fmt.Println("Src IP: ", t.SrcIP)
	return nil

}

// ICMP Header

// Build the entire Frame from ICMP6 fields
func (t *ICMP6) BuildICMPPacket() error {

	// first check if addresses are valid
	err := t.verifyAddr()
	if err != nil {
		fmt.Println("Problem with verifying your addresses")
		return err
	}

	var ip, icmp []byte
	bErr := errors.New("Cannot Build IPv6 and ICMP6 Headers")

	h := new(ip6Header)
	p := new(icmp6Header)

	/* need length now for IP header */
	if t.DataLen != len(t.Data) {
		fmt.Println("DataLen does not equal len(data)!")
	}
	p.PayloadLen = t.DataLen
	// debug
	//fmt.Println("payload len data:", p.PayloadLen)

	h.Version = 6
	h.TrafficClass = 0x00
	h.NextHeader = syscall.IPPROTO_ICMPV6
	h.HopLimit = 64
	h.Src = net.ParseIP(t.SrcIP)

	/* copy src to icmp struct for pseudo header */
	p.Src = net.ParseIP(t.SrcIP)
	h.Dst = net.ParseIP(t.DstIP)

	/* copy dst to icmp struct for pseudo header */
	p.Dst = net.ParseIP(t.DstIP)

	p.Type = int(t.Type)
	p.Code = t.Code

	p.Payload = make([]byte, 1500)

	// Build ICMP data from ICMP6 Struct
	offset := 0
	if t.Type == ICMPTypeParameterProblem {
		binary.BigEndian.PutUint32(p.Data[:4], t.ICMP6_pptr)
	} else if t.Type == ICMPTypePacketTooBig {
		binary.BigEndian.PutUint32(p.Data[:4], t.ICMP6_mtu)
	} else if t.Type == ICMPTypeEchoRequest || t.Type == ICMPTypeEchoReply {
		binary.BigEndian.PutUint16(p.Data[0:2], t.ICMP6_id)
		binary.BigEndian.PutUint16(p.Data[2:4], t.ICMP6_seq)
	} else if t.Type == ICMPTypeRouterSolicitation {
		// reserved
		binary.BigEndian.PutUint32(p.Data[0:4], uint32(0))

	} else if t.Type == ICMPTypeRouterAdvertisement {
		p.Data[0] = byte(t.RA_Curhoplimit)
		p.Data[1] = byte(t.RA_Flags)
		p.PayloadLen += 8
		offset = 8
		binary.BigEndian.PutUint16(p.Data[2:4], uint16(t.RA_Router_lifetime))
		binary.BigEndian.PutUint32(p.Payload[:4], uint32(t.RA_Reachable))
		binary.BigEndian.PutUint32(p.Payload[4:8], uint32(t.RA_Retransmit))
	} else if t.Type == ICMPTypeNeighborSolicitation {
		offset = 16
		p.PayloadLen += offset
		ip := net.ParseIP(t.TargetAddr)
		if ip == nil {
			fmt.Println("NS: could not parse target address")
			return bErr
		}
		addr := ip.To16()
		copy(p.Payload[0:16], addr)

	} else if t.Type == ICMPTypeNeighborAdvertisement {
		p.Data[0] = byte(t.NA_Flags)
		offset = 16
		p.PayloadLen += offset
		ip := net.ParseIP(t.TargetAddr)
		if ip == nil {
			fmt.Println("NA: could not parse target address")
			return bErr
		}
		addr := ip.To16()
		copy(p.Payload[0:16], addr)

	} else if t.Type == ICMPTypeRedirect {
		offset = 32
		p.PayloadLen += offset
		targetIP := net.ParseIP(t.TargetAddr)
		if targetIP == nil {
			fmt.Println("Redirect: could not parse target address")
			return bErr
		}
		addr := targetIP.To16()
		copy(p.Payload[0:16], addr)

		dstIP := net.ParseIP(t.DestAddr)
		if dstIP == nil {
			fmt.Println("Redirect: could not parse destination address")
			return bErr
		}
		addr = dstIP.To16()
		copy(p.Payload[16:32], addr)

	} else if t.Type == ICMPTypeMulticastListenerQuery ||
		t.Type == ICMPTypeMulticastListenerReport || t.Type == ICMPTypeMulticastListenerDone {

		binary.BigEndian.PutUint16(p.Data[:2], uint16(t.MLD_MaxDelay))
		binary.BigEndian.PutUint16(p.Data[2:4], uint16(0))

		offset = 16
		p.PayloadLen += offset
		ip := net.ParseIP(t.MLD_Addr)
		if ip == nil {
			fmt.Println("NS: could not parse MLD address")
			return bErr
		}
		addr := ip.To16()
		copy(p.Payload[0:16], addr)

	} else if t.Type == ICMPTypeRouterRenumbering {

		binary.BigEndian.PutUint32(p.Data[:4], uint32(t.RR_Seqnum))
		//fmt.Println("icmp data: ", p.Data[:4])

		// Segnum
		p.Payload[0] = byte(t.RR_Segnum)
		// Flags
		p.Payload[1] = byte(t.RR_Flags)
		// MaxDelay
		binary.BigEndian.PutUint16(p.Payload[2:4], uint16(t.RR_MaxDelay))
		// Reserved
		binary.BigEndian.PutUint32(p.Payload[4:8], uint32(0))

		// next pco match part
		p.Payload[8] = byte(t.RR_PCOMatch.Code)
		// Oplen not until we know how many UsePrefix parts
		p.Payload[10] = byte(t.RR_PCOMatch.Ordinal)
		p.Payload[11] = byte(t.RR_PCOMatch.MatchLen)
		p.Payload[12] = byte(t.RR_PCOMatch.MinLen)
		p.Payload[13] = byte(t.RR_PCOMatch.MaxLen)
		// Reserved
		binary.BigEndian.PutUint16(p.Payload[14:16], uint16(0))

		// Prefix
		ip := net.ParseIP(t.RR_PCOMatch.Prefix)
		if ip == nil {
			fmt.Println("NS: could not parse RR_PCOMatch prefix")
			return bErr
		}
		addr := ip.To16()
		copy(p.Payload[16:32], addr)

		// can be more than 1 RR Use
		i := 0
		for i, use := range t.RR_PCOUse {
			// base index
			b := 32 + (32 * i)
			p.Payload[b] = byte(use.UseLen)
			b++
			p.Payload[b] = byte(use.KeepLen)
			b++
			p.Payload[b] = byte(use.RA_Mask)
			b++
			p.Payload[b] = byte(use.RA_Flags)
			b++

			binary.BigEndian.PutUint32(p.Payload[b:b+4], uint32(use.ValidLifetime))
			b += 4
			binary.BigEndian.PutUint32(p.Payload[b:b+4], uint32(use.PreferedLifetime))
			b += 4
			binary.BigEndian.PutUint32(p.Payload[b:b+4], uint32(use.Flags))
			b += 4

			// Prefix
			ip := net.ParseIP(use.Prefix)
			if ip == nil {
				fmt.Println("NS: could not parse RR_PCOMatch prefix")
				return bErr
			}
			addr := ip.To16()
			copy(p.Payload[b:b+16], addr)
		}

		i++
		OpLen := (4 * i) + 3
		p.Payload[9] = byte(OpLen)
		offset = OpLen * 8
		p.PayloadLen += offset
	}

	// this will overwrite any data options above
	if t.UseICMPData == true {
		fmt.Println("over-writing ICMPData")
		copy(p.Data[:4], t.ICMPData[:4])
	}

	if len(t.Options) > 0 {
		opOff, err := t.buildOptions()
		if err != nil {
			fmt.Println("problem building options", err)
			return err
		}
		p.PayloadLen += opOff
	}
	h.PayloadLen = ICMPHeaderLen + p.PayloadLen

	// should take care of raw data and data tacked
	// on to options

	if len(t.Data)%2 != 0 {
		fmt.Println("Data must be on 16 bit boundry")
		return bErr
	}

	copy(p.Payload[offset:], t.Data[:])

	ip, err = h.marshal()
	if err != nil {
		return bErr
	}

	icmp, err = p.marshal()
	if err != nil {
		return bErr
	}

	t.frame = append(ip, icmp...)
	return nil
}

// build icmp6 header options and append to template data
func (t *ICMP6) buildOptions() (int, error) {
	offset := 0
	optErr := errors.New("Error buildOptions")
	for _, o := range t.Options {
		var optionData []byte

		switch o.Type {
		case OPT_SOURCE_LINKADDR:
			offset = 8
			optionData = make([]byte, offset)
			optionData[0] = OPT_SOURCE_LINKADDR
			optionData[1] = 1 /* length * 8 */
			addr, err := net.ParseMAC(o.Addr)
			if err != nil {
				fmt.Println("Could not Parse LinkAddr")
				return 0, optErr
			}
			copy(optionData[2:], addr)
		case OPT_TARGET_LINKADDR:
			offset = 8
			optionData = make([]byte, offset)
			optionData[0] = OPT_TARGET_LINKADDR
			optionData[1] = 1 /* length * 8 */
			addr, err := net.ParseMAC(o.Addr)
			if err != nil {
				fmt.Println("Could not Parse LinkAddr")
				return 0, optErr
			}
			copy(optionData[2:], addr)
		case OPT_PREFIX_INFORMATION:
			offset = 32
			optionData = make([]byte, offset)
			optionData[0] = OPT_PREFIX_INFORMATION
			optionData[1] = 4 /* length * 32 */
			optionData[2] = byte(o.PI_Prefix_Len)
			optionData[3] = o.PI_Flags
			binary.BigEndian.PutUint32(optionData[4:8], o.PI_Valid_Time)
			binary.BigEndian.PutUint32(optionData[8:12], o.PI_Pref_Time)
			/* 12 - 15 Reserved */
			addr := net.ParseIP(o.Addr).To16()
			if addr != nil {
				copy(optionData[16:32], addr)
			} else {
				fmt.Println("Bad IP6 Prefix Address")
				return 0, optErr
			}
		case OPT_REDIRECT_HEADER:
			/* not supported */
		case OPT_MTU:
			offset = 8
			optionData = make([]byte, offset)
			optionData[0] = OPT_MTU
			optionData[1] = 1 /* length * 8 */
			optionData[2] = 0
			optionData[3] = 0
			binary.BigEndian.PutUint32(optionData[4:], o.MTU)
		case OPT_RDNS:
			length := 0
			if o.RDNS_Server2 == "" {
				length = 3
			} else {
				length = 5
			}
			offset = length * 8
			optionData = make([]byte, offset)
			optionData[0] = OPT_RDNS
			optionData[1] = byte(length)
			binary.BigEndian.PutUint16(optionData[2:4], 0)
			binary.BigEndian.PutUint32(optionData[4:8], o.RDNS_Lifetime)

			addr := net.ParseIP(o.RDNS_Server1).To16()
			if addr != nil {
				copy(optionData[8:24], addr)
			} else {
				fmt.Println("Bad IP6 RDNS Server Address")
				return 0, optErr
			}
			if o.RDNS_Server2 != "" {

				addr = net.ParseIP(o.RDNS_Server2).To16()
				if addr != nil {
					copy(optionData[24:], addr)
				} else {
					fmt.Println("Bad IP6 RDNS Server Address")
					return 0, optErr
				}
			}

		default:

		}
		t.Data = append(t.Data, optionData...)
		t.DataLen += offset

	}
	return t.DataLen, nil
}

// Send ICMP6 Packet
// Must call BuildICMPPacket to build the frame before sending
func (t *ICMP6) Send() error {
	aErr := errors.New("Error building attack frame")

	if len(t.frame) == 0 {
		fmt.Println("Must build headers first!")
		return aErr
	}

	hwIface, err := net.InterfaceByName(t.Iface)
	if err != nil {
		fmt.Println(err)
		return aErr
	}
	// func NewDev(ifce *net.Interface, frameFilter FrameFilter) (dev Dev, err error)
	ff := func(frame ethernet.Frame) bool { return true }
	myDev, err := ether.NewDev(hwIface, ff)
	if err != nil {
		fmt.Println("Error getting interface", err)
		return aErr
	}

	myFrame := make(ethernet.Frame, 1500)
	pktlen := len(t.frame)
	for i, b := range t.frame {
		myFrame[EtherLen+i] = b
	}

	srcMac, err := net.ParseMAC(t.SrcMAC)
	if err != nil {
		fmt.Println("error parse Source MAC")
		return aErr
	}
	dstMac, err := net.ParseMAC(t.DstMAC)
	if err != nil {
		fmt.Println("error parse Destination MAC")
		return aErr
	}

	myFrame.Prepare(dstMac, srcMac, ethernet.NotTagged, ethernet.IPv6, pktlen)
	err = myDev.Write(myFrame)
	if err != nil {
		fmt.Println("Error write frame")
		return aErr
	}
	myDev.Close()
	return nil
}

// IPv6 Header will be build in BuildICMP
type ip6Header struct {
	Version      int
	TrafficClass int
	FlowLabel    int
	PayloadLen   int
	NextHeader   int
	HopLimit     int
	Src          net.IP
	Dst          net.IP
}

// Marshal returns the binary encoding of h.
func (h *ip6Header) marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}
	b := make([]byte, IPHeaderLen)
	/* ip6_flow */
	var ip6_flow uint32 = (uint32(h.Version) << 28) | (uint32(h.TrafficClass) << 20)
	ip6_flow |= uint32(h.FlowLabel)
	binary.BigEndian.PutUint32(b[0:4], ip6_flow)
	/* ip6_plen */
	binary.BigEndian.PutUint16(b[4:6], uint16(h.PayloadLen))
	b[6] = byte(h.NextHeader)
	b[7] = byte(h.HopLimit)
	if ip := h.Src.To16(); ip != nil {
		copy(b[8:24], ip[:net.IPv6len])
	}
	if ip := h.Dst.To16(); ip != nil {
		copy(b[24:40], ip[:net.IPv6len])
	} else {
		return nil, syscall.EINVAL // need to handle correctly
	}
	return b, nil
}

// Internal ICMP6 Header
type icmp6Header struct {
	Type       int
	Code       int
	Data       [4]byte
	PayloadLen int
	Payload    []byte
	Src        net.IP // for psdhdr
	Dst        net.IP
}

// Marshal returns the binary encoding of h.
func (h *icmp6Header) marshal() ([]byte, error) {
	if h == nil {
		return nil, syscall.EINVAL
	}
	b := make([]byte, ICMPHeaderLen+h.PayloadLen)
	/* type */
	b[0] = byte(h.Type)
	b[1] = byte(h.Code)
	b[2] = 0 // checksum 0 before calc
	b[3] = 0
	//fmt.Println("h.PayloadLen:", h.PayloadLen)
	copy(b[4:8], h.Data[:4])

	// debug
	//fmt.Println("buff data ", b[4:8], h.Data[:4])

	copy(b[8:8+h.PayloadLen], h.Payload[:h.PayloadLen])

	/* pseudo header for checksum */
	p := make([]byte, 40+ICMPHeaderLen+h.PayloadLen)
	if ip := h.Src.To16(); ip != nil {
		copy(p[0:16], ip[:net.IPv6len])
	}
	if ip := h.Dst.To16(); ip != nil {
		copy(p[16:32], ip[:net.IPv6len])
	} else {
		return nil, syscall.EINVAL // need to handle correctly
	}

	p[32] = 0
	p[33] = 0
	p[34] = byte((ICMPHeaderLen + h.PayloadLen) / 256)
	p[35] = byte((ICMPHeaderLen + h.PayloadLen) % 256)
	p[36] = 0
	p[37] = 0
	p[38] = 0
	p[39] = syscall.IPPROTO_ICMPV6

	copy(p[40:40+ICMPHeaderLen], b[0:ICMPHeaderLen])
	copy(p[40+ICMPHeaderLen:40+ICMPHeaderLen+h.PayloadLen], b[ICMPHeaderLen:ICMPHeaderLen+h.PayloadLen])

	cs := csum(p)
	b[2] = byte(cs)
	b[3] = byte(cs >> 8)
	return b, nil
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	// add back the carry
	s = s>>16 + s&0xffff
	s = s + s>>16
	return uint16(^s)
}

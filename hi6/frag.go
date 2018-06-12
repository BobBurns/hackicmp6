package hi6

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
)

func (t *ICMP6) SendFrag(file string) error {
	// pseudo code
	fErr := errors.New("Error with SendFrag")

	// check if frame has been built
	if len(t.frame) == 0 {
		fmt.Println("Must build headers first!")
		return fErr
	}

	// get some defs out of the way
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
	hwIface, err := net.InterfaceByName(t.Iface)
	if err != nil {
		fmt.Println(err)
		return fErr
	}

	// open file for reading
	data, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Println("Error opening file: ", file, err)
		return fErr
	}
	// build array of frames
	// TODO this is assuming ip6 and icmp6 headers are built

	// func NewDev(ifce *net.Interface, frameFilter FrameFilter) (dev Dev, err error)
	ff := func(frame ethernet.Frame) bool { return true }
	myDev, err := ether.NewDev(hwIface, ff)
	if err != nil {
		fmt.Println("Error getting interface", err)
		return aErr
	}

	myFrame := make(ethernet.Frame, 1500)
	pktlen := len(t.frame)

	// TODO first copy IP6 header and change next header to frag
	copy(myFrame[:IPHeaderLen], t.frame[:IPHeaderLen])
	// new payload length
	binary.BigEndian.PutUint16(myFrame[4:6], uint16(h.PayloadLen)) // this needs to be done later
	myFrame[6] = byte(44)                                          // Next Header = Fragment Header

	for i, b := range t.frame {
		myFrame[EtherLen+i] = b
	}

	myFrame.Prepare(dstMac, srcMac, ethernet.NotTagged, ethernet.IPv6, pktlen)
	err = myDev.Write(myFrame)
	if err != nil {
		fmt.Println("Error write frame")
		return aErr
	}
	myDev.Close()
	return nil
	// frag header + data
	// first frame has icmp6 header + data
	// each payload is data / 1500 - frag header

	// so first build the entire buffer, then
	// split into array of frames
	// if last frame then set last frag flag

	// how to determine data for different
	// payload types. ie na vs ra
}

package hi6

import (
	"net"
	"fmt"
)

func (t *ICMP6) SendFrag(file string) error {
	// pseudo code

	// open file for reading
	// build array of frames
	// frag header + data
	// first frame has icmp6 header + data
	// each payload is data / 1500 - frag header

	// so first build the entire buffer, then
	// split into array of frames
	// if last frame then set last frag flag

	// how to determine data for different
	// payload types. ie na vs ra
}

package hi6

// from https://godoc.org/golang.org/x/net/ipv6#pkg-constants

type ICMPType int

const (
    ICMPTypeDestinationUnreachable                ICMPType = 1   // Destination Unreachable
    ICMPTypePacketTooBig                          ICMPType = 2   // Packet Too Big
    ICMPTypeTimeExceeded                          ICMPType = 3   // Time Exceeded
    ICMPTypeParameterProblem                      ICMPType = 4   // Parameter Problem
    ICMPTypeEchoRequest                           ICMPType = 128 // Echo Request
    ICMPTypeEchoReply                             ICMPType = 129 // Echo Reply
    ICMPTypeMulticastListenerQuery                ICMPType = 130 // Multicast Listener Query
    ICMPTypeMulticastListenerReport               ICMPType = 131 // Multicast Listener Report
    ICMPTypeMulticastListenerDone                 ICMPType = 132 // Multicast Listener Done
    ICMPTypeRouterSolicitation                    ICMPType = 133 // Router Solicitation
    ICMPTypeRouterAdvertisement                   ICMPType = 134 // Router Advertisement
    ICMPTypeNeighborSolicitation                  ICMPType = 135 // Neighbor Solicitation
    ICMPTypeNeighborAdvertisement                 ICMPType = 136 // Neighbor Advertisement
    ICMPTypeRedirect                              ICMPType = 137 // Redirect Message
    ICMPTypeRouterRenumbering                     ICMPType = 138 // Router Renumbering
    ICMPTypeNodeInformationQuery                  ICMPType = 139 // ICMP Node Information Query
    ICMPTypeNodeInformationResponse               ICMPType = 140 // ICMP Node Information Response
    ICMPTypeInverseNeighborDiscoverySolicitation  ICMPType = 141 // Inverse Neighbor Discovery Solicitation Message
    ICMPTypeInverseNeighborDiscoveryAdvertisement ICMPType = 142 // Inverse Neighbor Discovery Advertisement Message
    ICMPTypeVersion2MulticastListenerReport       ICMPType = 143 // Version 2 Multicast Listener Report
    ICMPTypeHomeAgentAddressDiscoveryRequest      ICMPType = 144 // Home Agent Address Discovery Request Message
    ICMPTypeHomeAgentAddressDiscoveryReply        ICMPType = 145 // Home Agent Address Discovery Reply Message
    ICMPTypeMobilePrefixSolicitation              ICMPType = 146 // Mobile Prefix Solicitation
    ICMPTypeMobilePrefixAdvertisement             ICMPType = 147 // Mobile Prefix Advertisement
    ICMPTypeCertificationPathSolicitation         ICMPType = 148 // Certification Path Solicitation Message
    ICMPTypeCertificationPathAdvertisement        ICMPType = 149 // Certification Path Advertisement Message
    ICMPTypeMulticastRouterAdvertisement          ICMPType = 151 // Multicast Router Advertisement
    ICMPTypeMulticastRouterSolicitation           ICMPType = 152 // Multicast Router Solicitation
    ICMPTypeMulticastRouterTermination            ICMPType = 153 // Multicast Router Termination
    ICMPTypeFMIPv6                                ICMPType = 154 // FMIPv6 Messages
    ICMPTypeRPLControl                            ICMPType = 155 // RPL Control Message
    ICMPTypeILNPv6LocatorUpdate                   ICMPType = 156 // ILNPv6 Locator Update Message
    ICMPTypeDuplicateAddressRequest               ICMPType = 157 // Duplicate Address Request
    ICMPTypeDuplicateAddressConfirmation          ICMPType = 158 // Duplicate Address Confirmation
    ICMPTypeMPLControl                            ICMPType = 159 // MPL Control Message
    ICMPTypeExtendedEchoRequest                   ICMPType = 160 // Extended Echo Request
    ICMPTypeExtendedEchoReply                     ICMPType = 161 // Extended Echo Reply
)

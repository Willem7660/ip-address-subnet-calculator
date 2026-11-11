// Package ip_address_subnet_calculator computes the network address, broadcast
// address, usable host range, and wildcard mask for an IPv4 address given as a
// CIDR block.
//
// The library deliberately works on IPv4 only. IPv6 subnetting has a different
// mental model (no broadcast address, no wildcard mask, and host counts that
// overflow uint64), so mixing the two would force every caller to reason about
// which rules apply. One clear rule set beats a clever compromise.
package ip_address_subnet_calculator

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ErrInvalidCIDR is returned when the input cannot be parsed as an IPv4 CIDR
// block. Callers can use errors.Is to distinguish malformed input from other
// failures.
var ErrInvalidCIDR = errors.New("invalid IPv4 CIDR block")

// Subnet holds the computed properties of an IPv4 CIDR block.
//
// Network and Broadcast are the first and last addresses of the block.
// FirstHost and LastHost are the usable host addresses; for /31 and /32 blocks
// they are set equal to Network and Broadcast respectively, matching the
// convention that point-to-point and host routes have no reserved host range.
// Wildcard is the bitwise inverse of the mask, useful for ACLs.
// HostCount is the number of usable host addresses.
type Subnet struct {
	Network   net.IP
	Broadcast net.IP
	FirstHost net.IP
	LastHost  net.IP
	Wildcard  net.IP
	Mask      net.IP
	Prefix    int
	HostCount uint64
}

// ParseCIDR parses an IPv4 CIDR block such as "192.168.1.10/24".
//
// The host bits in the address are masked off, so the returned Subnet always
// describes the containing network rather than echoing back the input address.
// IPv6 inputs are rejected with ErrInvalidCIDR.
func ParseCIDR(cidr string) (Subnet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return Subnet{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, cidr)
	}
	if ip.To4() == nil {
		return Subnet{}, fmt.Errorf("%w: %q is not IPv4", ErrInvalidCIDR, cidr)
	}

	prefix, err := prefixFromMask(ipNet.Mask)
	if err != nil {
		return Subnet{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, cidr)
	}

	network := ip.Mask(ipNet.Mask).To4()
	if network == nil {
		return Subnet{}, fmt.Errorf("%w: %q", ErrInvalidCIDR, cidr)
	}

	return buildSubnet(network, prefix), nil
}

// FromIPAndPrefix builds a Subnet from an IPv4 address and a prefix length.
// This is the entry point when the prefix arrives separately from the address,
// for example from a config file with host and prefix fields.
func FromIPAndPrefix(ip net.IP, prefix int) (Subnet, error) {
	v4 := ip.To4()
	if v4 == nil {
		return Subnet{}, fmt.Errorf("%w: address is not IPv4", ErrInvalidCIDR)
	}
	if prefix < 0 || prefix > 32 {
		return Subnet{}, fmt.Errorf("%w: prefix %d out of range", ErrInvalidCIDR, prefix)
	}
	mask := net.CIDRMask(prefix, 32)
	network := v4.Mask(mask)
	return buildSubnet(network.To4(), prefix), nil
}

// buildSubnet fills in the derived fields. It assumes network is a 4-byte IPv4
// address already masked to prefix.
func buildSubnet(network net.IP, prefix int) Subnet {
	mask := net.CIDRMask(prefix, 32)
	wildcard := net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		wildcard[i] = ^mask[i]
	}

	broadcast := net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		broadcast[i] = network[i] | wildcard[i]
	}

	hostBits := 32 - prefix
	var hostCount uint64
	switch {
	case hostBits == 0:
		// /32: a single host route. The one address is usable.
		hostCount = 1
	case hostBits == 1:
		// /31: RFC 3021 point-to-point link. Both addresses are usable.
		hostCount = 2
	default:
		// Subtract network and broadcast addresses.
		hostCount = (uint64(1) << uint(hostBits)) - 2
	}

	firstHost := net.IP(make([]byte, 4))
	lastHost := net.IP(make([]byte, 4))
	if hostBits <= 1 {
		// No reserved addresses, so the host range is the whole block.
		copy(firstHost, network)
		copy(lastHost, broadcast)
	} else {
		copy(firstHost, network)
		firstHost[3]++
		copy(lastHost, broadcast)
		lastHost[3]--
	}

	return Subnet{
		Network:   cloneIP(network),
		Broadcast: broadcast,
		FirstHost: firstHost,
		LastHost:  lastHost,
		Wildcard:  wildcard,
		Mask:      net.IP(mask),
		Prefix:    prefix,
		HostCount: hostCount,
	}
}

// cloneIP returns a fresh 4-byte copy so callers cannot mutate our internal
// slices through the returned value.
func cloneIP(ip net.IP) net.IP {
	out := make([]byte, 4)
	copy(out, ip.To4())
	return out
}

// prefixFromMask converts a net.IPMask into a prefix length. It rejects masks
// that are not contiguous, which can happen if a caller constructs one by hand.
func prefixFromMask(mask net.IPMask) (int, error) {
	if len(mask) != 4 {
		return 0, errors.New("mask is not IPv4")
	}
	ones, bits := mask.Size()
	if ones == 0 && bits == 0 {
		return 0, errors.New("non-contiguous mask")
	}
	if bits != 32 {
		return 0, errors.New("mask is not 32 bits")
	}
	return ones, nil
}

// String renders the subnet as a CIDR block, for example "192.168.1.0/24".
func (s Subnet) String() string {
	return s.Network.String() + "/" + strconv.Itoa(s.Prefix)
}

// Contains reports whether ip falls inside the subnet, including the network
// and broadcast addresses.
func (s Subnet) Contains(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if v4[i]&s.Mask[i] != s.Network[i] {
			return false
		}
	}
	return true
}

// Format renders a human-readable summary. It is intentionally terse so it can
// be embedded in logs without a parser.
func (s Subnet) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "network=%s broadcast=%s range=%s-%s wildcard=%s hosts=%d",
		s.Network, s.Broadcast, s.FirstHost, s.LastHost, s.Wildcard, s.HostCount)
	return b.String()
}

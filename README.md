# ip-address-subnet-calculator

Computes the network address, broadcast address, usable host range, wildcard mask, and host count for an IPv4 CIDR block.

```go
package main

import (
	"fmt"

	subnet "github.com/example/ip-address-subnet-calculator"
)

func main() {
	s, err := subnet.ParseCIDR("192.168.1.10/24")
	if err != nil {
		panic(err)
	}
	fmt.Println(s.Network)   // 192.168.1.0
	fmt.Println(s.Broadcast) // 192.168.1.255
	fmt.Println(s.FirstHost) // 192.168.1.1
	fmt.Println(s.LastHost)  // 192.168.1.254
	fmt.Println(s.Wildcard)  // 0.0.0.255
	fmt.Println(s.Format())  // network=192.168.1.0 broadcast=192.168.1.255 range=192.168.1.1-192.168.1.254 wildcard=0.0.0.255 hosts=254
}
```

If the address and prefix arrive separately, use `FromIPAndPrefix`:

```go
s, err := subnet.FromIPAndPrefix(net.ParseIP("172.16.5.9"), 20)
// s.Network is 172.16.0.0, s.Broadcast is 172.16.15.255
```

## Why this exists

Subnet maths is a handful of bit operations, but every project that needs it rewrites the same masking, broadcast, and host-range logic, and usually gets one of the small cases wrong. This library centralises that in a single function that returns a plain struct, so callers can read the fields they need without re-deriving anything.

The trade-off: it is IPv4-only. IPv6 has no broadcast address and no wildcard mask, and its host counts do not fit in a `uint64` for large prefixes, so supporting both would mean either two APIs or one API full of conditionals. IPv6 inputs are rejected with `ErrInvalidCIDR` rather than silently mis-handled.

## The awkward edge

`/31` and `/32` blocks do not follow the usual "subtract two" rule. A `/31` is a point-to-point link (RFC 3021) where both addresses are usable, and a `/32` is a single host route where the one address is usable. In both cases `FirstHost` and `LastHost` are set to the endpoints of the block and `HostCount` is `2` and `1` respectively, rather than the `0` you would get from the naive formula. Every other prefix subtracts the network and broadcast addresses as usual.

## API

- `ParseCIDR(cidr string) (Subnet, error)` — parses an IPv4 CIDR block. Host bits in the input are masked off.
- `FromIPAndPrefix(ip net.IP, prefix int) (Subnet, error)` — builds a subnet from a separate address and prefix.
- `ErrInvalidCIDR` — sentinel error returned for malformed input; use `errors.Is` to check.
- `Subnet` fields: `Network`, `Broadcast`, `FirstHost`, `LastHost`, `Wildcard`, `Mask`, `Prefix`, `HostCount`.
- `(Subnet) Contains(ip net.IP) bool` — reports whether an address falls inside the block, including network and broadcast.
- `(Subnet) String() string` — renders the block as `network/prefix`.
- `(Subnet) Format() string` — renders a terse one-line summary.

All returned `net.IP` values are 4-byte IPv4 addresses in their own backing slices, so mutating one does not affect a later call.

package ip_address_subnet_calculator

import (
	"errors"
	"net"
	"testing"
)

func mustSubnet(t *testing.T, cidr string) Subnet {
	t.Helper()
	s, err := ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q) returned error: %v", cidr, err)
	}
	return s
}

func TestParseCIDRTypicalSlash24(t *testing.T) {
	s := mustSubnet(t, "192.168.1.10/24")

	if got, want := s.Network.String(), "192.168.1.0"; got != want {
		t.Errorf("Network = %s, want %s", got, want)
	}
	if got, want := s.Broadcast.String(), "192.168.1.255"; got != want {
		t.Errorf("Broadcast = %s, want %s", got, want)
	}
	if got, want := s.FirstHost.String(), "192.168.1.1"; got != want {
		t.Errorf("FirstHost = %s, want %s", got, want)
	}
	if got, want := s.LastHost.String(), "192.168.1.254"; got != want {
		t.Errorf("LastHost = %s, want %s", got, want)
	}
	if got, want := s.Wildcard.String(), "0.0.0.255"; got != want {
		t.Errorf("Wildcard = %s, want %s", got, want)
	}
	if got, want := s.Prefix, 24; got != want {
		t.Errorf("Prefix = %d, want %d", got, want)
	}
	if got, want := s.HostCount, uint64(254); got != want {
		t.Errorf("HostCount = %d, want %d", got, want)
	}
}

func TestParseCIDRHostBitsAreMasked(t *testing.T) {
	// The input address has host bits set; the network must not echo them.
	s := mustSubnet(t, "10.20.30.40/8")
	if got, want := s.Network.String(), "10.0.0.0"; got != want {
		t.Errorf("Network = %s, want %s", got, want)
	}
	if got, want := s.Broadcast.String(), "10.255.255.255"; got != want {
		t.Errorf("Broadcast = %s, want %s", got, want)
	}
	if got, want := s.HostCount, uint64(16777214); got != want {
		t.Errorf("HostCount = %d, want %d", got, want)
	}
}

func TestParseCIDRSlash31PointToPoint(t *testing.T) {
	// RFC 3021: both addresses on a /31 are usable.
	s := mustSubnet(t, "192.0.2.4/31")
	if got, want := s.Network.String(), "192.0.2.4"; got != want {
		t.Errorf("Network = %s, want %s", got, want)
	}
	if got, want := s.Broadcast.String(), "192.0.2.5"; got != want {
		t.Errorf("Broadcast = %s, want %s", got, want)
	}
	if got, want := s.FirstHost.String(), "192.0.2.4"; got != want {
		t.Errorf("FirstHost = %s, want %s", got, want)
	}
	if got, want := s.LastHost.String(), "192.0.2.5"; got != want {
		t.Errorf("LastHost = %s, want %s", got, want)
	}
	if got, want := s.HostCount, uint64(2); got != want {
		t.Errorf("HostCount = %d, want %d", got, want)
	}
}

func TestParseCIDRSlash32SingleHost(t *testing.T) {
	s := mustSubnet(t, "203.0.113.7/32")
	if got, want := s.Network.String(), "203.0.113.7"; got != want {
		t.Errorf("Network = %s, want %s", got, want)
	}
	if got, want := s.Broadcast.String(), "203.0.113.7"; got != want {
		t.Errorf("Broadcast = %s, want %s", got, want)
	}
	if got, want := s.FirstHost.String(), "203.0.113.7"; got != want {
		t.Errorf("FirstHost = %s, want %s", got, want)
	}
	if got, want := s.LastHost.String(), "203.0.113.7"; got != want {
		t.Errorf("LastHost = %s, want %s", got, want)
	}
	if got, want := s.HostCount, uint64(1); got != want {
		t.Errorf("HostCount = %d, want %d", got, want)
	}
}

func TestParseCIDRSlash30(t *testing.T) {
	s := mustSubnet(t, "198.51.100.0/30")
	if got, want := s.FirstHost.String(), "198.51.100.1"; got != want {
		t.Errorf("FirstHost = %s, want %s", got, want)
	}
	if got, want := s.LastHost.String(), "198.51.100.2"; got != want {
		t.Errorf("LastHost = %s, want %s", got, want)
	}
	if got, want := s.HostCount, uint64(2); got != want {
		t.Errorf("HostCount = %d, want %d", got, want)
	}
}

func TestParseCIDRRejectsIPv6(t *testing.T) {
	_, err := ParseCIDR("2001:db8::/32")
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR")
	}
	if !errors.Is(err, ErrInvalidCIDR) {
		t.Errorf("error = %v, want ErrInvalidCIDR", err)
	}
}

func TestParseCIDRRejectsGarbage(t *testing.T) {
	for _, in := range []string{"", "not-a-cidr", "192.168.1.1", "192.168.1.1/33", "192.168.1.1/-1"} {
		_, err := ParseCIDR(in)
		if err == nil {
			t.Errorf("ParseCIDR(%q) expected error, got nil", in)
			continue
		}
		if !errors.Is(err, ErrInvalidCIDR) {
			t.Errorf("ParseCIDR(%q) error = %v, want ErrInvalidCIDR", in, err)
		}
	}
}

func TestFromIPAndPrefix(t *testing.T) {
	s, err := FromIPAndPrefix(net.ParseIP("172.16.5.9"), 20)
	if err != nil {
		t.Fatalf("FromIPAndPrefix returned error: %v", err)
	}
	if got, want := s.Network.String(), "172.16.0.0"; got != want {
		t.Errorf("Network = %s, want %s", got, want)
	}
	if got, want := s.Broadcast.String(), "172.16.15.255"; got != want {
		t.Errorf("Broadcast = %s, want %s", got, want)
	}
	if got, want := s.Wildcard.String(), "0.0.15.255"; got != want {
		t.Errorf("Wildcard = %s, want %s", got, want)
	}
	if got, want := s.Prefix, 20; got != want {
		t.Errorf("Prefix = %d, want %d", got, want)
	}
}

func TestFromIPAndPrefixRejectsBadInput(t *testing.T) {
	if _, err := FromIPAndPrefix(net.ParseIP("2001:db8::1"), 64); err == nil {
		t.Error("expected error for IPv6 address")
	}
	if _, err := FromIPAndPrefix(net.ParseIP("10.0.0.1"), 33); err == nil {
		t.Error("expected error for prefix 33")
	}
	if _, err := FromIPAndPrefix(net.ParseIP("10.0.0.1"), -1); err == nil {
		t.Error("expected error for negative prefix")
	}
}

func TestContains(t *testing.T) {
	s := mustSubnet(t, "192.168.1.0/24")
	inside := []string{"192.168.1.0", "192.168.1.1", "192.168.1.255"}
	for _, ip := range inside {
		if !s.Contains(net.ParseIP(ip)) {
			t.Errorf("Contains(%s) = false, want true", ip)
		}
	}
	outside := []string{"192.168.2.1", "10.0.0.1", "2001:db8::1"}
	for _, ip := range outside {
		if s.Contains(net.ParseIP(ip)) {
			t.Errorf("Contains(%s) = true, want false", ip)
		}
	}
}

func TestStringAndFormat(t *testing.T) {
	s := mustSubnet(t, "192.168.1.10/24")
	if got, want := s.String(), "192.168.1.0/24"; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
	want := "network=192.168.1.0 broadcast=192.168.1.255 range=192.168.1.1-192.168.1.254 wildcard=0.0.0.255 hosts=254"
	if got := s.Format(); got != want {
		t.Errorf("Format() = %s, want %s", got, want)
	}
}

func TestReturnedSlicesAreIndependent(t *testing.T) {
	// Mutating the returned Network must not affect a second call.
	s1 := mustSubnet(t, "192.168.1.0/24")
	s1.Network[0] = 0
	s2 := mustSubnet(t, "192.168.1.0/24")
	if got, want := s2.Network.String(), "192.168.1.0"; got != want {
		t.Errorf("Network after mutation = %s, want %s", got, want)
	}
}

// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package discover

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/miekg/dns"
)

func TestTagText(t *testing.T) {
	if got := TagText([4]byte{0xde, 0xad, 0xbe, 0xef}); got != "tag=deadbeef" {
		t.Fatal(got)
	}
	if Service != "_transporter._tcp" || DefaultTimeout != 5*time.Second {
		t.Fatal("DISC-1/DISC-3 constants changed")
	}
}

type logBuf struct{ strings.Builder }

func (l *logBuf) Write(p []byte) (int, error) { return l.Builder.Write(p) }

// TestAdvertiseAndFind covers DISC-1 and DISC-2: two receivers advertise
// different tags; the browser finds the one with its tag. It is skipped
// when multicast does not work in the environment (DISC-5), as is common in
// CI containers.
func TestAdvertiseAndFind(t *testing.T) {
	var lb logBuf
	m := MDNS{Logger: slog.New(slog.NewTextHandler(&lb, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tagA, tagB := [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}
	a, err := m.Advertise(ctx, 41111, tagA)
	if err != nil {
		t.Skipf("multicast unavailable (cannot start mDNS responder): %v", err)
	}
	defer a.Close()
	b, err := m.Advertise(ctx, 42222, tagB)
	if err != nil {
		t.Skipf("multicast unavailable: %v", err)
	}
	defer b.Close()
	addr, err := m.Find(ctx, tagB, 3*time.Second)
	if errors.Is(err, ErrNotFound) {
		t.Logf("library log:\n%s", lb.String())
		t.Skipf("multicast unavailable (no mDNS answers received): %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(addr)
	if port != strconv.Itoa(42222) {
		t.Fatalf("found %s, want port 42222", addr)
	}
	if strings.Contains(lb.String(), "abandon") {
		t.Fatal("log mentions code material")
	}
}

// TestFindTimeout covers DISC-3: without a matching receiver, Find gives up
// after the timeout with ErrNotFound.
func TestFindTimeout(t *testing.T) {
	start := time.Now()
	_, err := MDNS{}.Find(context.Background(), [4]byte{9, 9, 9, 9}, 300*time.Millisecond)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("took %v", took)
	}
	if _, err := (MDNS{}).Find(context.Background(), [4]byte{}, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("default timeout: %v", err)
	}
}

// TestServiceRecords covers DISC-1 and CODE-7 without multicast: the
// advertised records carry the service type, port, tag and version, and
// nothing else.
func TestServiceRecords(t *testing.T) {
	tag := [4]byte{0xca, 0xfe, 0xba, 0xbe}
	svc, err := newService(4321, tag, []net.IP{net.ParseIP("192.0.2.7")})
	if err != nil {
		t.Fatal(err)
	}
	if svc.Port != 4321 || svc.Service != Service || !strings.HasPrefix(svc.Instance, "transfer-") || svc.HostName != svc.Instance+".local." {
		t.Fatalf("service %+v", svc)
	}
	if len(svc.TXT) != 2 || svc.TXT[0] != "tag=cafebabe" || svc.TXT[1] != "v=1" {
		t.Fatalf("TXT %v", svc.TXT)
	}
	other, err := newService(4321, tag, []net.IP{net.ParseIP("192.0.2.8")})
	if err != nil {
		t.Fatal(err)
	}
	if other.Instance == svc.Instance {
		t.Fatal("instance names are not random")
	}
}

// TestMatch covers DISC-2: only answers with the right tag and a usable
// address are chosen.
func TestMatch(t *testing.T) {
	want := TagText([4]byte{1, 2, 3, 4})
	v6 := &net.IPAddr{IP: net.ParseIP("2001:db8::1")}
	ll := &net.IPAddr{IP: net.ParseIP("fe80::1")}
	tests := []struct {
		e    *mdns.ServiceEntry
		want string
	}{
		{&mdns.ServiceEntry{InfoFields: []string{want}, Port: 5000, AddrV4: net.ParseIP("192.0.2.1")}, "192.0.2.1:5000"},
		{&mdns.ServiceEntry{InfoFields: []string{"v=1", want}, Port: 5000, AddrV6IPAddr: v6}, "[2001:db8::1]:5000"},
		{&mdns.ServiceEntry{InfoFields: []string{"tag=00000000"}, Port: 5000, AddrV4: net.ParseIP("192.0.2.1")}, ""},
		{&mdns.ServiceEntry{InfoFields: []string{want}, Port: 0, AddrV4: net.ParseIP("192.0.2.1")}, ""},
		{&mdns.ServiceEntry{InfoFields: []string{want}, Port: 5000}, ""},
		{&mdns.ServiceEntry{InfoFields: []string{want}, Port: 5000, AddrV6IPAddr: ll}, ""},
		{nil, ""},
	}
	for i, tc := range tests {
		got, ok := match(tc.e, want)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("case %d: %q %v", i, got, ok)
		}
	}
}

// useInterfaces makes multicastInterfaces return ifaces for one test; nil
// means the system default only.
func useInterfaces(t *testing.T, ifaces ...*net.Interface) {
	t.Helper()
	old := multicastInterfaces
	t.Cleanup(func() { multicastInterfaces = old })
	multicastInterfaces = func() []*net.Interface { return ifaces }
}

// family names the address families a query enabled.
func family(p *mdns.QueryParam) string {
	return map[[2]bool]string{
		{false, false}: "both", {false, true}: "v4", {true, false}: "v6",
	}[[2]bool{p.DisableIPv4, p.DisableIPv6}]
}

// fakeQuery replaces the library query for one test, on the system default
// interface only. It records which address families each call enabled,
// fails calls that enable IPv6 (as the library does when the IPv6 send
// fails), and answers IPv4-only calls with entry, if given.
func fakeQuery(t *testing.T, entry *mdns.ServiceEntry) *[]string {
	t.Helper()
	useInterfaces(t)
	var calls []string
	old := queryContext
	t.Cleanup(func() { queryContext = old })
	queryContext = func(ctx context.Context, p *mdns.QueryParam) error {
		calls = append(calls, family(p))
		if !p.DisableIPv6 {
			return errors.New("sendto: no route to host")
		}
		if entry != nil {
			p.Entries <- entry
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(p.Timeout):
		}
		return nil
	}
	return &calls
}

// TestFindFallsBackToIPv4 covers DISC-1 and DISC-3: when the IPv6 send
// fails (as on macOS without an IPv6 multicast route), the library fails
// the whole query; Find retries on IPv4 alone and finds the receiver.
func TestFindFallsBackToIPv4(t *testing.T) {
	tag := [4]byte{1, 2, 3, 4}
	calls := fakeQuery(t, &mdns.ServiceEntry{
		AddrV4: net.IPv4(192, 0, 2, 7), Port: 41111, InfoFields: []string{TagText(tag)},
	})
	addr, err := MDNS{}.Find(context.Background(), tag, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "192.0.2.7:41111" {
		t.Fatalf("addr %q", addr)
	}
	if got := strings.Join(*calls, ","); got != "both,v4" {
		t.Fatalf("calls %s, want both,v4", got)
	}
}

// TestFindFailureWaitsForTimeout covers DISC-3: when no family can send,
// Find keeps trying until the timeout instead of failing at once, then
// reports ErrNotFound with the cause.
func TestFindFailureWaitsForTimeout(t *testing.T) {
	useInterfaces(t)
	old := queryContext
	t.Cleanup(func() { queryContext = old })
	n := 0
	queryContext = func(context.Context, *mdns.QueryParam) error {
		n++
		return errors.New("failed to bind to any multicast udp port")
	}
	start := time.Now()
	_, err := MDNS{}.Find(context.Background(), [4]byte{1}, time.Second)
	if took := time.Since(start); took < time.Second || took > 2*time.Second {
		t.Fatalf("took %v, want about 1s", took)
	}
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "multicast") {
		t.Fatalf("err %v", err)
	}
	if n < 6 { // several rounds of three attempts
		t.Fatalf("only %d attempts", n)
	}
}

// TestFindPrefersWorkingFamily checks that after a fallback the working
// family is tried first, so later rounds don't repeat the failing send.
func TestFindPrefersWorkingFamily(t *testing.T) {
	calls := fakeQuery(t, nil)
	_, err := MDNS{}.Find(context.Background(), [4]byte{1}, 2500*time.Millisecond)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
	got := strings.Join(*calls, ",")
	if !strings.HasPrefix(got, "both,v4,v4") || strings.Count(got, "both") != 1 {
		t.Fatalf("calls %s, want both then only v4", got)
	}
}

// TestFindQueriesEveryInterface covers DISC-1 and DISC-2 on a multi-homed
// sender: every round queries on each interface, each interface keeps its
// own address-family fallback, and the receiver is found on the interface
// that is not the first one.
func TestFindQueriesEveryInterface(t *testing.T) {
	tag := [4]byte{1, 2, 3, 4}
	wifi := &net.Interface{Index: 7, Name: "wlan0"}
	wired := &net.Interface{Index: 8, Name: "eth1"}
	useInterfaces(t, wifi, wired)
	var mu sync.Mutex
	calls := map[string][]string{}
	old := queryContext
	t.Cleanup(func() { queryContext = old })
	queryContext = func(ctx context.Context, p *mdns.QueryParam) error {
		if p.Interface == nil {
			t.Error("query on the default interface, want a named one")
			return errors.New("no interface")
		}
		mu.Lock()
		calls[p.Interface.Name] = append(calls[p.Interface.Name], family(p))
		round := len(calls[p.Interface.Name])
		mu.Unlock()
		switch p.Interface.Name {
		case "wlan0": // no IPv6 multicast route; no receiver
			if !p.DisableIPv6 {
				return errors.New("sendto: no route to host")
			}
		case "eth1": // the receiver, found in the second round
			if round >= 2 {
				p.Entries <- &mdns.ServiceEntry{AddrV4: net.IPv4(192, 0, 2, 9), Port: 41111, InfoFields: []string{TagText(tag)}}
				return nil
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
		return nil
	}
	addr, err := MDNS{}.Find(context.Background(), tag, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "192.0.2.9:41111" {
		t.Fatalf("addr %q", addr)
	}
	if got := strings.Join(calls["wlan0"], ","); got != "both,v4,v4" {
		t.Errorf("wlan0 calls %s, want both,v4,v4", got)
	}
	if got := strings.Join(calls["eth1"], ","); got != "both,both" {
		t.Errorf("eth1 calls %s, want both,both", got)
	}
}

// TestFindReportsInterface checks that a failure names the interface.
func TestFindReportsInterface(t *testing.T) {
	useInterfaces(t, &net.Interface{Index: 3, Name: "eth9"})
	old := queryContext
	t.Cleanup(func() { queryContext = old })
	queryContext = func(context.Context, *mdns.QueryParam) error { return errors.New("sendto: network is down") }
	_, err := MDNS{}.Find(context.Background(), [4]byte{1}, 300*time.Millisecond)
	if !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "eth9: sendto") {
		t.Fatalf("err %v", err)
	}
}

// TestPick covers DISC-2 with a multi-homed receiver: of its answers, the
// address on the sender's own subnet wins over a container or VPN address,
// then IPv4 over IPv6.
func TestPick(t *testing.T) {
	want := TagText([4]byte{1, 2, 3, 4})
	v4 := func(ip string) *mdns.ServiceEntry {
		return &mdns.ServiceEntry{InfoFields: []string{want}, Port: 5000, AddrV4: net.ParseIP(ip)}
	}
	v6 := func(ip string) *mdns.ServiceEntry {
		return &mdns.ServiceEntry{InfoFields: []string{want}, Port: 5000, AddrV6IPAddr: &net.IPAddr{IP: net.ParseIP(ip)}}
	}
	other := &mdns.ServiceEntry{InfoFields: []string{"tag=00000000"}, Port: 6000, AddrV4: net.ParseIP("10.5.1.50")}
	local := []netip.Prefix{
		netip.MustParsePrefix("10.5.1.20/24"),
		netip.MustParsePrefix("172.17.0.1/16"), // the sender's own docker0
		netip.MustParsePrefix("2001:db8:1::20/64"),
	}
	tests := []struct {
		name    string
		entries []*mdns.ServiceEntry
		want    string
	}{
		{"local after container", []*mdns.ServiceEntry{v4("172.17.0.1"), v4("10.5.1.88")}, "10.5.1.88:5000"},
		{"local IPv6 over remote IPv4", []*mdns.ServiceEntry{v4("172.17.0.1"), v6("2001:db8:1::5")}, "[2001:db8:1::5]:5000"},
		{"IPv4 over IPv6", []*mdns.ServiceEntry{v6("2001:db8:2::5"), v4("192.0.2.1")}, "192.0.2.1:5000"},
		// Both machines run Docker: the receiver's docker0 address is the
		// sender's own and would connect the sender to itself.
		{"shared docker0 before LAN", []*mdns.ServiceEntry{v4("172.17.0.1"), v4("10.5.1.88")}, "10.5.1.88:5000"},
		{"own address after IPv6", []*mdns.ServiceEntry{v4("172.17.0.1"), v6("2001:db8:2::5")}, "[2001:db8:2::5]:5000"},
		{"same machine", []*mdns.ServiceEntry{v4("172.17.0.1"), v4("10.5.1.20")}, "172.17.0.1:5000"},
		{"first of equals", []*mdns.ServiceEntry{v4("192.0.2.1"), v4("192.0.2.2")}, "192.0.2.1:5000"},
		{"other tag on my subnet", []*mdns.ServiceEntry{other, v4("192.0.2.1")}, "192.0.2.1:5000"},
		{"nothing", []*mdns.ServiceEntry{other, nil}, ""},
	}
	for _, tc := range tests {
		got, ok := pick(tc.entries, want, local)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: %q %v, want %q", tc.name, got, ok, tc.want)
		}
	}
}

// TestZone covers DISC-1 for a multi-homed receiver: each address is its
// own service instance with its own host name and that address alone, so
// the sender's library keeps every address instead of the last one.
func TestZone(t *testing.T) {
	tag := [4]byte{0xca, 0xfe, 0xba, 0xbe}
	z, err := newZone(4321, tag, []net.IP{net.ParseIP("10.5.1.88"), net.ParseIP("172.17.0.1"), net.ParseIP("2001:db8::7")})
	if err != nil {
		t.Fatal(err)
	}
	recs := z.Records(dns.Question{Name: Service + ".local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET})
	ptrs, hosts := map[string]bool{}, map[string]string{}
	for _, rr := range recs {
		switch rr := rr.(type) {
		case *dns.PTR:
			ptrs[rr.Ptr] = true
		case *dns.A:
			if _, dup := hosts[rr.Hdr.Name]; dup {
				t.Errorf("host %s has two addresses", rr.Hdr.Name)
			}
			hosts[rr.Hdr.Name] = rr.A.String()
		case *dns.AAAA:
			if _, dup := hosts[rr.Hdr.Name]; dup {
				t.Errorf("host %s has two addresses", rr.Hdr.Name)
			}
			hosts[rr.Hdr.Name] = rr.AAAA.String()
		}
	}
	if len(ptrs) != 3 || len(hosts) != 3 {
		t.Fatalf("%d instances and %d hosts, want 3 each: %v", len(ptrs), len(hosts), recs)
	}
	got := slices.Sorted(func(yield func(string) bool) {
		for _, a := range hosts {
			if !yield(a) {
				return
			}
		}
	})
	if strings.Join(got, ",") != "10.5.1.88,172.17.0.1,2001:db8::7" {
		t.Fatalf("addresses %v", got)
	}
	if _, err := newZone(4321, tag, nil); err == nil {
		t.Fatal("empty zone accepted")
	}
}

type fakeServer struct{ down *int }

func (f fakeServer) Shutdown() error { *f.down++; return nil }

// TestAdvertiseEveryInterface covers DISC-1 on a multi-homed receiver: a
// responder runs on each interface, one that fails does not stop the
// others, and Close stops them all.
func TestAdvertiseEveryInterface(t *testing.T) {
	useInterfaces(t, &net.Interface{Index: 2, Name: "eth0"}, &net.Interface{Index: 3, Name: "wg0"}, &net.Interface{Index: 4, Name: "wlan0"})
	var started []string
	down := 0
	old := newServer
	t.Cleanup(func() { newServer = old })
	newServer = func(c *mdns.Config) (shutdowner, error) {
		if c.Zone == nil {
			t.Error("no zone")
		}
		name := ifaceName(c.Iface)
		if name == "wg0" {
			return nil, errors.New("no multicast listeners could be started")
		}
		started = append(started, name)
		return fakeServer{&down}, nil
	}
	c, err := MDNS{}.Advertise(context.Background(), 4321, [4]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(started, ","); got != "eth0,wlan0" {
		t.Fatalf("responders on %s, want eth0,wlan0", got)
	}
	if err := c.Close(); err != nil || down != 2 {
		t.Fatalf("Close: %v, %d shut down", err, down)
	}
}

// TestAdvertiseFallsBackToDefault checks that a receiver whose interfaces
// all fail (or that has none) still tries the system default, and that
// failing there too is an error naming the causes.
func TestAdvertiseFallsBackToDefault(t *testing.T) {
	useInterfaces(t, &net.Interface{Index: 2, Name: "eth0"})
	var tried []string
	ok := true
	old := newServer
	t.Cleanup(func() { newServer = old })
	newServer = func(c *mdns.Config) (shutdowner, error) {
		tried = append(tried, ifaceName(c.Iface))
		if c.Iface != nil || !ok {
			return nil, errors.New("bind failed")
		}
		return fakeServer{new(int)}, nil
	}
	c, err := MDNS{}.Advertise(context.Background(), 4321, [4]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if got := strings.Join(tried, ","); got != "eth0,default interface" {
		t.Fatalf("tried %s", got)
	}
	ok, tried = false, nil
	if _, err := (MDNS{}).Advertise(context.Background(), 4321, [4]byte{1}); err == nil || !strings.Contains(err.Error(), "eth0: bind failed") {
		t.Fatalf("err %v", err)
	}
}

// TestInterfaceFlags covers which interfaces mDNS and the advertised
// addresses use: up, with a carrier, multicast capable, not loopback. An
// unused Docker bridge (up, no carrier) is left out.
func TestInterfaceFlags(t *testing.T) {
	up, run, mc, lo := net.FlagUp, net.FlagRunning, net.FlagMulticast, net.FlagLoopback
	tests := []struct {
		f             net.Flags
		carrier, mdns bool
	}{
		{up | run | mc | net.FlagBroadcast, true, true}, // a LAN interface
		{up | mc | net.FlagBroadcast, false, false},     // docker0, NO-CARRIER
		{run | mc, false, false},                        // down
		{up | run, true, false},                         // no multicast
		{up | run | mc | lo, true, false},               // loopback
	}
	for i, tc := range tests {
		if carrierUp(tc.f) != tc.carrier || multicastCapable(tc.f) != tc.mdns {
			t.Errorf("case %d (%v): carrierUp %v, multicastCapable %v", i, tc.f, carrierUp(tc.f), multicastCapable(tc.f))
		}
	}
}

// TestRoutable covers which interfaces mDNS uses: only those with an
// address a receiver could be reached at. macOS's awdl0 and llw0, and
// bridge members, have link-local addresses only, or none.
func TestRoutable(t *testing.T) {
	ipn := func(cidr string) net.Addr {
		ip, n, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	tests := []struct {
		name  string
		addrs []net.Addr
		want  bool
	}{
		{"LAN IPv4", []net.Addr{ipn("fe80::1/64"), ipn("10.5.1.189/24")}, true},
		{"global IPv6 only", []net.Addr{ipn("2001:db8::5/64")}, true},
		{"awdl0: link-local only", []net.Addr{ipn("fe80::1/64")}, false},
		{"IPv4 link-local", []net.Addr{ipn("169.254.10.1/16")}, false},
		{"loopback", []net.Addr{ipn("127.0.0.1/8"), ipn("::1/128")}, false},
		{"bridge member: none", nil, false},
		{"not an IPNet", []net.Addr{&net.IPAddr{IP: net.ParseIP("10.0.0.1")}}, false},
	}
	for _, tc := range tests {
		if got := routable(tc.addrs); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

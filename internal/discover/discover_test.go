// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package discover

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/mdns"
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

// fakeQuery replaces the library query for one test. It records which
// address families each call enabled, fails calls that enable IPv6 (as
// the library does when the IPv6 send fails), and answers IPv4-only calls
// with entry, if given.
func fakeQuery(t *testing.T, entry *mdns.ServiceEntry) *[]string {
	t.Helper()
	var calls []string
	old := queryContext
	t.Cleanup(func() { queryContext = old })
	queryContext = func(ctx context.Context, p *mdns.QueryParam) error {
		calls = append(calls, map[[2]bool]string{
			{false, false}: "both", {false, true}: "v4", {true, false}: "v6",
		}[[2]bool{p.DisableIPv4, p.DisableIPv6}])
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

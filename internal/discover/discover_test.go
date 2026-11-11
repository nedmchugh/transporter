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
	if svc.Port != 4321 || svc.Service != Service || !strings.HasPrefix(svc.Instance, "transfer-") {
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

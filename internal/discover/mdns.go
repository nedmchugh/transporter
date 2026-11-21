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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/mdns"
	"github.com/miekg/dns"

	"github.com/nedmchugh/transporter/internal/code"
)

// MDNS implements Advertiser and Browser with github.com/hashicorp/mdns
// (docs/DECISIONS.md section 1.5). The library's own log output is routed
// to Logger at debug level, so it never reaches the terminal by default.
type MDNS struct {
	Logger *slog.Logger
}

func (m MDNS) libLogger() *log.Logger {
	if m.Logger == nil {
		return log.New(io.Discard, "", 0)
	}
	return log.New(slogWriter{m.Logger}, "", 0)
}

// slogWriter adapts the library's *log.Logger output to slog.
type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Write(p []byte) (int, error) {
	w.l.Debug("mdns", "msg", strings.TrimSpace(string(p)))
	return len(p), nil
}

// Advertise implements Advertiser. The TXT record carries only the
// discovery tag and protocol version (DISC-1, CODE-7). The instance names
// are random, so they reveal nothing about the user or the code.
//
// A responder runs on every interface of multicastInterfaces, because a
// multicast listener joins the mDNS group on one interface only: with a
// single responder, queries arriving on the machine's other networks were
// never seen. A responder that fails on one interface only disables that
// interface. If none starts, one more is tried on the system's default
// multicast interface.
func (m MDNS) Advertise(ctx context.Context, port int, tag [code.TagSize]byte) (Closer, error) {
	zone, err := newZone(port, tag, advertisedIPs())
	if err != nil {
		return nil, err
	}
	var servers []shutdowner
	var errs []error
	start := func(ifc *net.Interface) {
		srv, err := newServer(&mdns.Config{Zone: zone, Iface: ifc, Logger: m.libLogger()})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ifaceName(ifc), err))
			return
		}
		servers = append(servers, srv)
	}
	for _, ifc := range multicastInterfaces() {
		start(ifc)
	}
	if len(servers) == 0 {
		start(nil)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("mdns: starting responder: %w", errors.Join(errs...))
	}
	for _, err := range errs {
		m.logger().Debug("mdns: no responder on an interface", "err", err)
	}
	shutdown := func() {
		for _, srv := range servers {
			_ = srv.Shutdown()
		}
	}
	stop := context.AfterFunc(ctx, shutdown)
	return closerFunc(func() error {
		stop()
		shutdown()
		return nil
	}), nil
}

// shutdowner is a running responder.
type shutdowner interface{ Shutdown() error }

// newServer starts the library responder, a variable so tests can see
// which interfaces are used and simulate ones on which it fails.
var newServer = func(c *mdns.Config) (shutdowner, error) {
	srv, err := mdns.NewServer(c)
	if err != nil {
		return nil, err
	}
	return srv, nil
}

func (m MDNS) logger() *slog.Logger {
	if m.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return m.Logger
}

// ifaceName names an interface in errors; nil is the system default.
func ifaceName(ifc *net.Interface) string {
	if ifc == nil {
		return "default interface"
	}
	return ifc.Name
}

// multicastInterfaces returns the interfaces mDNS runs on: up, running
// (with a carrier, so an unused Docker bridge is left out), multicast
// capable, not loopback, and with at least one address. Loopback is not
// needed for a receiver on the same machine, because multicast sent on an
// interface is looped back to local listeners. It is a variable so tests
// can choose the interfaces.
var multicastInterfaces = func() []*net.Interface {
	ifaces, _ := net.Interfaces()
	var out []*net.Interface
	for i := range ifaces {
		ifc := &ifaces[i]
		if !multicastCapable(ifc.Flags) {
			continue
		}
		if addrs, err := ifc.Addrs(); err != nil || len(addrs) == 0 {
			continue
		}
		out = append(out, ifc)
	}
	return out
}

// multicastCapable reports whether an interface with flags f can carry
// mDNS for multicastInterfaces.
func multicastCapable(f net.Flags) bool {
	return carrierUp(f) && f&net.FlagMulticast != 0 && f&net.FlagLoopback == 0
}

// carrierUp reports whether an interface with flags f is up and running:
// administratively up and with a carrier.
func carrierUp(f net.Flags) bool { return f&net.FlagUp != 0 && f&net.FlagRunning != 0 }

// newZone builds the DNS-SD records for a receiver: one service instance
// per address, each with its own random instance and host name and that
// address alone. The library keeps only one address per host name from an
// answer (the last A record), so with all addresses under one name the
// sender got an arbitrary one, possibly a container or VPN address it
// cannot reach. With one instance per address it sees all of them and
// picks one on its own subnet (see pick).
func newZone(port int, tag [code.TagSize]byte, ips []net.IP) (zone, error) {
	if len(ips) == 0 {
		return nil, errors.New("mdns: no address to advertise")
	}
	z := make(zone, 0, len(ips))
	for _, ip := range ips {
		svc, err := newService(port, tag, []net.IP{ip})
		if err != nil {
			return nil, err
		}
		z = append(z, svc)
	}
	return z, nil
}

// zone answers with the records of every service in it.
type zone []*mdns.MDNSService

func (z zone) Records(q dns.Question) []dns.RR {
	var out []dns.RR
	for _, svc := range z {
		out = append(out, svc.Records(q)...)
	}
	return out
}

// newService builds the DNS-SD records for one address of a receiver.
func newService(port int, tag [code.TagSize]byte, ips []net.IP) (*mdns.MDNSService, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	instance := "transfer-" + hex.EncodeToString(b[:])
	// The SRV target is a random name too, not the machine's host name:
	// that would reveal the host name on the LAN and could clash with the
	// system's own mDNS responder (docs/DECISIONS.md D-5b.1).
	svc, err := mdns.NewMDNSService(instance, Service, "", instance+".local.", port, ips, []string{TagText(tag), "v=1"})
	if err != nil {
		return nil, fmt.Errorf("mdns: building service record: %w", err)
	}
	return svc, nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

// advertisedIPs returns the non-loopback unicast addresses of up, running
// interfaces, or loopback if there are none (matching the receiver banner,
// RCV-4). Interfaces without a carrier, such as an unused Docker bridge,
// are left out: their addresses cannot be reached from the LAN.
func advertisedIPs() []net.IP {
	var out, loop []net.IP
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if !carrierUp(ifc.Flags) {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipn.IP.IsLoopback() {
				loop = append(loop, ipn.IP)
			} else {
				out = append(out, ipn.IP)
			}
		}
	}
	if len(out) == 0 {
		return loop
	}
	return out
}

// familyModes are the address-family combinations Find tries, in order.
var familyModes = []struct{ noV4, noV6 bool }{
	{false, false}, // both
	{false, true},  // IPv4 only
	{true, false},  // IPv6 only
}

// retryPause is the wait between rounds in which every family failed.
const retryPause = 250 * time.Millisecond

// queryContext is the library query, a variable so tests can simulate
// send failures on one address family.
var queryContext = mdns.QueryContext

// Find implements Browser: it queries for Service and returns an answer
// whose TXT record carries tag (DISC-2). Answers for other tags (other
// receivers on the LAN) are ignored.
//
// Each round queries on every interface of multicastInterfaces at once,
// because the library sends a query on one interface only, by default
// the one the system picks for multicast. A receiver on another of the
// sender's networks was never asked.
func (m MDNS) Find(ctx context.Context, tag [code.TagSize]byte, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	want := TagText(tag)
	ifaces := multicastInterfaces()
	if len(ifaces) == 0 {
		ifaces = []*net.Interface{nil} // the system default
	}
	local := localPrefixes()
	// The query is repeated within the timeout, because multicast packets
	// are easily lost and a receiver may start a moment after the sender.
	// The library fails the whole query when sending on either address
	// family fails (macOS without an IPv6 multicast route, for example),
	// before it listens for answers. So a failed query is retried on IPv4
	// alone and then IPv6 alone, and the family that works is used first
	// on that interface from then on. If none works on any interface, the
	// loop pauses briefly and tries again until the timeout (DISC-3), in
	// case the network is still coming up.
	modes := make([]int, len(ifaces))
	results := make([]queryResult, len(ifaces))
	var qerr error
	for ctx.Err() == nil {
		var wg sync.WaitGroup
		for i, ifc := range ifaces {
			mode := modes[i]
			wg.Go(func() { results[i] = m.query(ctx, ifc, mode, timeout) })
		}
		wg.Wait()
		ok := false
		var entries []*mdns.ServiceEntry
		for i, r := range results {
			entries = append(entries, r.entries...)
			if r.err == nil {
				modes[i], ok = r.mode, true
			} else {
				qerr = r.err
			}
		}
		if addr, hit := pick(entries, want, local); hit {
			return addr, nil
		}
		if !ok && ctx.Err() == nil {
			select {
			case <-ctx.Done():
			case <-time.After(retryPause):
			}
		}
	}
	if qerr != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFound, qerr)
	}
	return "", ErrNotFound
}

// queryResult is one interface's part of a Find round: the answers, the
// address-family mode that worked, or the last error if none did.
type queryResult struct {
	entries []*mdns.ServiceEntry
	mode    int
	err     error
}

// query runs one query on ifc (nil: the system default), trying the
// address-family modes from mode on until one sends.
func (m MDNS) query(ctx context.Context, ifc *net.Interface, mode int, timeout time.Duration) queryResult {
	// The library sends each answer as a pointer and keeps writing to the
	// same struct when later packets for that service arrive, so answers
	// are only read after QueryContext has returned (docs/DECISIONS.md
	// D-5b.5). Each query has its own channel, so no library writes to
	// another's answers. The library drops answers when the channel is
	// full, so it is sized well above any realistic number of receivers
	// on one LAN; the query repeats in any case.
	entries := make(chan *mdns.ServiceEntry, 256)
	var r queryResult
	for i := range familyModes {
		k := (mode + i) % len(familyModes)
		fm := familyModes[k]
		params := mdns.DefaultParams(Service)
		params.Entries = entries
		params.Timeout = min(time.Second, timeout)
		params.Logger = m.libLogger()
		params.Interface = ifc
		params.DisableIPv4, params.DisableIPv6 = fm.noV4, fm.noV6
		err := queryContext(ctx, params)
		if err == nil || ctx.Err() != nil {
			r.mode, r.err = k, nil
			break
		}
		r.err = fmt.Errorf("%s: %w", ifaceName(ifc), err)
	}
	for len(entries) > 0 {
		r.entries = append(r.entries, <-entries)
	}
	return r
}

// localPrefixes returns the sender's own addresses with their prefix
// lengths, so they give both the addresses and the subnets.
func localPrefixes() []netip.Prefix {
	addrs, _ := net.InterfaceAddrs()
	var out []netip.Prefix
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		ones, bits := ipn.Mask.Size()
		if !ok || bits == 0 {
			continue
		}
		if ip.Is4In6() && bits == 128 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return out
}

// pick chooses among the answers that carry the wanted tag (see match):
// an address on one of the sender's own subnets (local) first, then any
// IPv4 address, then IPv6, then one of the sender's own addresses, in the
// order received otherwise. A receiver answers once per address, and some
// of them (a VPN or container address) may be unreachable from the sender.
// An address the sender has itself is, on another machine, a per-host
// bridge such as docker0 (172.17.0.1 on both), and connecting to it
// reaches the sender; it is only right when both run on one machine, and
// then every address of the receiver is one of the sender's own.
func pick(entries []*mdns.ServiceEntry, want string, local []netip.Prefix) (string, bool) {
	best, bestRank := "", 4
	for _, e := range entries {
		addr, ok := match(e, want)
		if !ok {
			continue
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			continue
		}
		ip := ap.Addr()
		rank := 2
		switch {
		case slices.ContainsFunc(local, func(p netip.Prefix) bool { return p.Addr() == ip }):
			rank = 3
		case slices.ContainsFunc(local, func(p netip.Prefix) bool { return p.Contains(ip) }):
			rank = 0
		case ip.Is4():
			rank = 1
		}
		if rank < bestRank {
			best, bestRank = addr, rank
		}
	}
	return best, best != ""
}

// match returns the address of an answer carrying the wanted tag. Answers
// for other tags (other receivers on the LAN) are ignored (DISC-2), as are
// answers without a usable address.
func match(e *mdns.ServiceEntry, want string) (string, bool) {
	if e == nil || !slices.Contains(e.InfoFields, want) || e.Port <= 0 || e.Port > 65535 {
		return "", false
	}
	switch {
	case e.AddrV4 != nil:
		return net.JoinHostPort(e.AddrV4.String(), strconv.Itoa(e.Port)), true
	case e.AddrV6IPAddr != nil && !e.AddrV6IPAddr.IP.IsLinkLocalUnicast():
		return net.JoinHostPort(e.AddrV6IPAddr.IP.String(), strconv.Itoa(e.Port)), true
	}
	return "", false
}

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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/nedmchugh/transporter/internal/code"
)

// SweepPort is the default UDP port a receiver listens on for sweep probes
// (DISC-6). IANA lists it as unassigned, and it is below the ephemeral port
// ranges of Linux, macOS and Windows (docs/DECISIONS.md D-5b.7).
const SweepPort = 29873

// SweepTimeout is how long the sender sweeps after mDNS found nothing
// (DISC-7).
const SweepTimeout = 3 * time.Second

// Wire format (docs/protocol.md section 9). A probe is
//
//	"TRSQ" | version 1 | tag (4 bytes) | nonce (8 bytes)      17 bytes
//
// and a reply is
//
//	"TRSR" | version 1 | nonce (8 bytes) | TCP port (2 bytes)  15 bytes
//
// The reply is shorter than the probe, so a spoofed probe cannot be used
// to amplify traffic towards a third party.
const (
	probeMagic   = "TRSQ"
	replyMagic   = "TRSR"
	sweepVersion = 1
	nonceSize    = 8
	probeSize    = 4 + 1 + code.TagSize + nonceSize
	replySize    = 4 + 1 + nonceSize + 2
)

// Sweep limits: a subnet larger than maxSweepPrefix is swept only in the
// block of that size around the sender's own address, and no more than
// maxSweepTargets addresses are probed in all.
const (
	maxSweepPrefix  = 22 // 1,022 hosts
	maxSweepTargets = 4096
)

// Pacing: probes go out in batches with a pause between them, so a round
// over a /22 takes about 0.3 s, and a new round starts every second.
// Repeating covers lost packets and a receiver that starts late.
const (
	sweepBatch = 64
	sweepPause = 20 * time.Millisecond
	sweepRound = time.Second
)

// Sweep implements Advertiser and Browser with a UDP unicast sweep, the
// fallback for networks that drop multicast (DISC-6 to DISC-9). The
// receiver listens on a UDP port; the sender sends a small probe carrying
// the discovery tag to every address on its local IPv4 subnets, and the
// receiver with that tag replies with its TCP port.
type Sweep struct {
	// Port is the UDP port; 0 means SweepPort.
	Port int
	// Bind is the address the receiver listens on; "" means all IPv4
	// interfaces.
	Bind string
	// Targets returns the addresses to probe; nil means SweepTargets.
	Targets func() []netip.Addr
	Logger  *slog.Logger
}

func (s Sweep) port() int {
	if s.Port == 0 {
		return SweepPort
	}
	return s.Port
}

func (s Sweep) logger() *slog.Logger {
	if s.Logger == nil {
		return slog.New(slog.DiscardHandler)
	}
	return s.Logger
}

// Advertise implements Advertiser: it answers probes that carry tag with
// tcpPort until ctx is done or Close is called. Probes with other tags, and
// anything else, are ignored without a reply.
func (s Sweep) Advertise(ctx context.Context, tcpPort int, tag [code.TagSize]byte) (Closer, error) {
	r, err := s.listen(ctx, tcpPort, tag)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// responder is a running sweep responder.
type responder struct {
	conn *net.UDPConn
	stop func() bool
	wg   sync.WaitGroup
}

func (r *responder) Close() error {
	r.stop()
	err := r.conn.Close()
	r.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// addr is the bound address, for tests that listen on port 0.
func (r *responder) addr() netip.AddrPort { return r.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (s Sweep) listen(ctx context.Context, tcpPort int, tag [code.TagSize]byte) (*responder, error) {
	if tcpPort <= 0 || tcpPort > 65535 {
		return nil, fmt.Errorf("sweep: invalid TCP port %d", tcpPort)
	}
	host := s.Bind
	if ip := net.ParseIP(host); ip != nil {
		switch {
		case ip.IsUnspecified():
			host = ""
		case ip.To4() == nil:
			return nil, errors.New("sweep: --bind is an IPv6 address, and the sweep is IPv4 only")
		}
	}
	pc, err := net.ListenPacket("udp4", net.JoinHostPort(host, strconv.Itoa(s.port())))
	if err != nil {
		return nil, fmt.Errorf("sweep: listening for probes: %w", err)
	}
	r := &responder{conn: pc.(*net.UDPConn)}
	r.stop = context.AfterFunc(ctx, func() { _ = r.conn.Close() })
	log := s.logger()
	var reply [replySize]byte
	copy(reply[:], replyMagic)
	reply[4] = sweepVersion
	binary.BigEndian.PutUint16(reply[5+nonceSize:], uint16(tcpPort)) //nolint:gosec // checked above
	r.wg.Go(func() {
		var buf [64]byte
		for {
			n, from, err := r.conn.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue // transient, for example ICMP errors on Windows
			}
			nonce, ok := parseProbe(buf[:n], tag)
			if !ok {
				continue
			}
			copy(reply[5:5+nonceSize], nonce[:])
			if _, err := r.conn.WriteToUDPAddrPort(reply[:], from); err != nil {
				log.Debug("sweep: reply failed", "to", from, "err", err)
				continue
			}
			log.Debug("sweep: answered a probe", "from", from)
		}
	})
	return r, nil
}

// Find implements Browser: it probes every target on the UDP port, in
// rounds, and returns "host:port" of the first receiver that answers with
// this probe's nonce (DISC-7). Only a receiver with tag answers (DISC-2).
func (s Sweep) Find(ctx context.Context, tag [code.TagSize]byte, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = SweepTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	targetsOf := s.Targets
	if targetsOf == nil {
		targetsOf = SweepTargets
	}
	targets := targetsOf()
	if len(targets) == 0 {
		return "", fmt.Errorf("%w: no IPv4 network to sweep", ErrNotFound)
	}
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	probe := makeProbe(tag, nonce)

	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return "", fmt.Errorf("%w: sweep: %w", ErrNotFound, err)
	}
	found := make(chan string, 1)
	var wg sync.WaitGroup
	// Close the socket, which ends the reader, and wait for it, so no
	// goroutine outlives Find (REL-6).
	defer wg.Wait()
	defer func() { _ = conn.Close() }()
	wg.Go(func() {
		var buf [64]byte
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue // transient, for example ICMP errors on Windows
			}
			port, ok := parseReply(buf[:n], nonce)
			if !ok {
				continue
			}
			found <- netip.AddrPortFrom(from.Addr().Unmap(), port).String()
			return
		}
	})

	log := s.logger()
	port := uint16(s.port()) //nolint:gosec // a port number
	var sendErr error
	wait := func(d time.Duration) (string, bool) {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case addr := <-found:
			return addr, true
		case <-ctx.Done():
		case <-t.C:
		}
		return "", false
	}
	for ctx.Err() == nil {
		start := time.Now()
		for i, ip := range targets {
			// Errors for single targets (no route, buffer full, a firewall)
			// do not stop the sweep; the last one is reported on failure.
			if _, err := conn.WriteToUDPAddrPort(probe, netip.AddrPortFrom(ip, port)); err != nil {
				sendErr = err
			}
			if (i+1)%sweepBatch == 0 {
				if addr, ok := wait(sweepPause); ok {
					return addr, nil
				}
				if ctx.Err() != nil {
					break
				}
			}
		}
		log.Debug("sweep: probed", "targets", len(targets), "port", port)
		if addr, ok := wait(time.Until(start.Add(sweepRound))); ok {
			return addr, nil
		}
	}
	// An answer that arrived together with the timeout still counts.
	select {
	case addr := <-found:
		return addr, nil
	default:
	}
	if sendErr != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFound, sendErr)
	}
	return "", ErrNotFound
}

func makeProbe(tag [code.TagSize]byte, nonce [nonceSize]byte) []byte {
	p := make([]byte, 0, probeSize)
	p = append(p, probeMagic...)
	p = append(p, sweepVersion)
	p = append(p, tag[:]...)
	return append(p, nonce[:]...)
}

// parseProbe returns the nonce of a probe carrying tag.
func parseProbe(p []byte, tag [code.TagSize]byte) ([nonceSize]byte, bool) {
	var nonce [nonceSize]byte
	if len(p) != probeSize || string(p[:4]) != probeMagic || p[4] != sweepVersion || [code.TagSize]byte(p[5:5+code.TagSize]) != tag {
		return nonce, false
	}
	copy(nonce[:], p[5+code.TagSize:])
	return nonce, true
}

// parseReply returns the TCP port of a reply to the probe with nonce.
func parseReply(p []byte, nonce [nonceSize]byte) (uint16, bool) {
	if len(p) != replySize || string(p[:4]) != replyMagic || p[4] != sweepVersion || [nonceSize]byte(p[5:5+nonceSize]) != nonce {
		return 0, false
	}
	port := binary.BigEndian.Uint16(p[5+nonceSize:])
	return port, port != 0
}

// SweepTargets returns the addresses the sender probes: 127.0.0.1, for a
// receiver on the same machine, then the other addresses of each local
// IPv4 subnet on an up, running, non-loopback interface (DISC-8).
func SweepTargets() []netip.Addr {
	var nets []netip.Prefix
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		// Interfaces that are down or have no carrier (an unused Docker
		// bridge, for example) are skipped.
		if !carrierUp(ifc.Flags) || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			ones, bits := ipn.Mask.Size()
			if !ok || bits != 32 && bits != 128 {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if bits == 128 { // an IPv4 address with a 16-byte mask
				ones -= 96
			}
			nets = append(nets, netip.PrefixFrom(ip, ones))
		}
	}
	return sweepTargets(nets)
}

// sweepTargets expands the local addresses (each with its prefix length)
// into the addresses to probe, without duplicates or the local addresses
// themselves, up to maxSweepTargets. The subnets take turns, one address
// each, so when the cap is reached every subnet has had an even share: a
// few large subnets listed first (container bridges, a VPN) cannot use up
// the cap before the LAN is reached.
func sweepTargets(local []netip.Prefix) []netip.Addr {
	self := map[netip.Addr]bool{}
	for _, p := range local {
		self[p.Addr()] = true
	}
	loop := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	out := []netip.Addr{loop}
	seen := map[netip.Addr]bool{loop: true}
	var lists [][]netip.Addr
	for _, p := range local {
		if hosts := subnetHosts(p); len(hosts) > 0 {
			lists = append(lists, hosts)
		}
	}
	for len(lists) > 0 {
		left := lists[:0]
		for _, hosts := range lists {
			// Take this subnet's next new address; addresses already
			// taken (from an overlapping subnet) are skipped, not counted.
			for len(hosts) > 0 {
				ip := hosts[0]
				hosts = hosts[1:]
				if seen[ip] || self[ip] {
					continue
				}
				if len(out) == maxSweepTargets {
					return out
				}
				seen[ip] = true
				out = append(out, ip)
				break
			}
			if len(hosts) > 0 {
				left = append(left, hosts)
			}
		}
		lists = left
	}
	return out
}

// subnetHosts lists the host addresses of the IPv4 subnet p belongs to.
// The network and broadcast addresses are left out, except on /31 links,
// which have neither (RFC 3021). A subnet larger than maxSweepPrefix is
// cut to the block of that size around p's address; every address of that
// block is then a possible host.
func subnetHosts(p netip.Prefix) []netip.Addr {
	if !p.Addr().Is4() || p.Bits() < 0 || p.Bits() >= 32 {
		return nil
	}
	bits := p.Bits()
	whole := bits >= maxSweepPrefix
	if !whole {
		bits = maxSweepPrefix
	}
	base := p.Addr().As4()
	first := binary.BigEndian.Uint32(base[:]) &^ (1<<(32-bits) - 1)
	size := uint32(1) << (32 - bits)
	lo, hi := uint32(0), size-1
	if whole && bits <= 30 {
		lo, hi = 1, size-2
	}
	out := make([]netip.Addr, 0, hi-lo+1)
	for i := lo; i <= hi; i++ {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], first+i)
		out = append(out, netip.AddrFrom4(b))
	}
	return out
}

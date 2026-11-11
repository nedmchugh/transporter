// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/mdns"

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
// discovery tag and protocol version (DISC-1, CODE-7). The instance name is
// random, so it reveals nothing about the user or the code.
func (m MDNS) Advertise(ctx context.Context, port int, tag [code.TagSize]byte) (Closer, error) {
	svc, err := newService(port, tag, advertisedIPs())
	if err != nil {
		return nil, err
	}
	srv, err := mdns.NewServer(&mdns.Config{Zone: svc, Logger: m.libLogger()})
	if err != nil {
		return nil, fmt.Errorf("mdns: starting responder: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = srv.Shutdown() })
	return closerFunc(func() error {
		stop()
		return srv.Shutdown()
	}), nil
}

// newService builds the DNS-SD records for a receiver.
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

// advertisedIPs returns the non-loopback unicast addresses of up interfaces,
// or loopback if there are none (matching the receiver banner, RCV-4).
func advertisedIPs() []net.IP {
	var out, loop []net.IP
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
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

// Find implements Browser: it queries for Service and returns the first
// answer whose TXT record carries tag (DISC-2). Answers for other tags
// (other receivers on the LAN) are ignored.
func (m MDNS) Find(ctx context.Context, tag [code.TagSize]byte, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	want := TagText(tag)
	entries := make(chan *mdns.ServiceEntry, 16)
	found := make(chan string, 1)
	go func() {
		for e := range entries {
			addr, ok := match(e, want)
			if !ok {
				continue
			}
			select {
			case found <- addr:
				cancel()
			default:
			}
		}
	}()
	// The query is repeated within the timeout, because multicast packets
	// are easily lost and a receiver may start a moment after the sender.
	var qerr error
	for ctx.Err() == nil {
		params := mdns.DefaultParams(Service)
		params.Entries = entries
		params.Timeout = min(time.Second, timeout)
		params.Logger = m.libLogger()
		if err := mdns.QueryContext(ctx, params); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			qerr = err
			break
		}
		select {
		case addr := <-found:
			close(entries)
			return addr, nil
		default:
		}
	}
	close(entries)
	select {
	case addr := <-found:
		return addr, nil
	default:
	}
	if qerr != nil {
		return "", fmt.Errorf("%w: %w", ErrNotFound, qerr)
	}
	return "", ErrNotFound
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

// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Ned McHugh

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/discover"
)

// discovery says which discovery methods are enabled (DISC-1, DISC-6).
type discovery struct {
	mdns      bool
	sweep     bool
	sweepPort int
}

// advertise makes the receiver discoverable with every enabled method
// until ctx ends; the returned function stops it. A method that fails only
// disables itself (the sender can still use the other one, or --to), so
// failures are logged as warnings, not fatal.
func advertise(ctx context.Context, port int, tag [code.TagSize]byte, d discovery, bind string, log *slog.Logger) func() {
	var closers []discover.Closer
	if d.mdns {
		var adv discover.Advertiser = discover.MDNS{Logger: log}
		if c, err := adv.Advertise(ctx, port, tag); err != nil {
			log.Warn("mDNS advertisement failed; senders must use the UDP sweep or --to", "err", err)
		} else {
			closers = append(closers, c)
		}
	}
	if d.sweep {
		if ip := net.ParseIP(bind); ip != nil && ip.To4() == nil && !ip.IsUnspecified() {
			log.Info("not answering the UDP sweep: it is IPv4 only and --bind is an IPv6 address")
		} else {
			var adv discover.Advertiser = discover.Sweep{Port: d.sweepPort, Bind: bind, Logger: log}
			if c, err := adv.Advertise(ctx, port, tag); err != nil {
				log.Warn("cannot answer the UDP sweep; senders must use mDNS or --to", "udp-port", d.sweepPort, "err", err)
			} else {
				closers = append(closers, c)
			}
		}
	}
	return func() {
		for _, c := range closers {
			_ = c.Close()
		}
	}
}

// discoveryTimeout is the longest browse can take with d.
func discoveryTimeout(d discovery) time.Duration {
	var t time.Duration
	if d.mdns {
		t += discover.DefaultTimeout
	}
	if d.sweep {
		t += discover.SweepTimeout
	}
	return t
}

// browse finds a receiver advertising tag (DISC-2): with mDNS first, then,
// only if that found nothing, with the UDP sweep (DISC-7).
func browse(ctx context.Context, tag [code.TagSize]byte, d discovery, log *slog.Logger) (string, error) {
	var why []string
	if d.mdns {
		var b discover.Browser = discover.MDNS{Logger: log}
		addr, err := b.Find(ctx, tag, discover.DefaultTimeout)
		if err == nil {
			return addr, nil
		}
		if ctx.Err() != nil {
			return "", err
		}
		why = append(why, "mDNS: "+reason(err))
		if d.sweep {
			log.Info("mDNS found no receiver; sweeping the local network", "udp-port", d.sweepPort)
		}
	}
	if d.sweep {
		var b discover.Browser = discover.Sweep{Port: d.sweepPort, Logger: log}
		addr, err := b.Find(ctx, tag, discover.SweepTimeout)
		if err == nil {
			return addr, nil
		}
		if ctx.Err() != nil {
			return "", err
		}
		why = append(why, "UDP sweep: "+reason(err))
	}
	return "", notFound(strings.Join(why, "; "))
}

// reason describes a discovery failure briefly: "no answer", with the
// underlying error if there was one.
func reason(err error) string {
	if !errors.Is(err, discover.ErrNotFound) {
		return err.Error()
	}
	cause := strings.TrimPrefix(strings.TrimPrefix(err.Error(), discover.ErrNotFound.Error()), ": ")
	if cause == "" {
		return "no answer"
	}
	return "no answer (" + cause + ")"
}

// notFound is a discovery failure; it matches discover.ErrNotFound.
type notFound string

func (e notFound) Error() string { return string(e) }
func (e notFound) Unwrap() error { return discover.ErrNotFound }

// discoveryHint is the DISC-3 hint for a failed discovery with d.
func discoveryHint(d discovery) string {
	h := "use --to HOST:PORT with an address the receiver printed"
	if d.mdns {
		h += "; mDNS is often blocked on guest and corporate networks"
	}
	if d.sweep {
		h += fmt.Sprintf("; the UDP sweep needs UDP port %d open on the receiving machine and only reaches the local subnet", d.sweepPort)
	}
	return h
}

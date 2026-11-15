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
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/nedmchugh/transporter/internal/code"
	"github.com/nedmchugh/transporter/internal/fail"
	"github.com/nedmchugh/transporter/internal/meta"
	"github.com/nedmchugh/transporter/internal/pairing"
	"github.com/nedmchugh/transporter/internal/proto"
	"github.com/nedmchugh/transporter/internal/recv"
)

const receiveUsage = `Usage: %[1]s receive [flags] [DEST]

Wait for one sender and write what it sends into DEST (default: the current
directory, created if missing). Prints the listening address(es) and a
one-time code on stdout; give the code to the sender. Exits after one
successful transfer.

Flags:
  --port N             TCP port to listen on (default 0: a random free port)
  --bind ADDR          address to listen on (default "": all interfaces, so
                       senders on the LAN can connect)
  --overwrite          replace existing files that differ (default false:
                       keep them and report a conflict)
  --verify             compare file contents by hash instead of size and
                       modification time (default false)
  --idle-timeout DUR   give up after this long without sender activity
                       (default 10m0s; 0 waits forever)
  --no-mdns            do not advertise on the local network with mDNS
                       (default false)
  --no-sweep           do not answer senders' UDP sweep probes (default
                       false)
  --sweep-port N       UDP port to answer the sweep on (default %[2]d)
  -v, --verbose        more log output; repeat for debug (default: warnings
                       and errors only)
`

// receiveFlags holds parsed receive options.
type receiveFlags struct {
	port        int
	bind        string
	overwrite   bool
	verify      bool
	idleTimeout time.Duration
	noMDNS      bool
	noSweep     bool
	sweepPort   int
	dest        string
}

// addReceiveFlags defines the receive flags (RCV-3). Help text lives in
// receiveUsage; the names here are also the config file keys under
// "receive" (configKeys).
func addReceiveFlags(fs *pflag.FlagSet) {
	fs.Int("port", 0, "")
	fs.String("bind", "", "")
	fs.Bool("overwrite", false, "")
	fs.Bool("verify", false, "")
	fs.Duration("idle-timeout", recv.DefaultIdleTimeout, "")
	fs.Bool("no-mdns", false, "")
	addSweepFlags(fs)
}

// receiveFlagsFrom reads the parsed receive flags (command line and config
// file already merged) and the destination argument, and checks them.
func receiveFlagsFrom(c *cobra.Command, args []string) (*receiveFlags, error) {
	fl := c.Flags()
	f := &receiveFlags{}
	f.port, _ = fl.GetInt("port")
	f.bind, _ = fl.GetString("bind")
	f.overwrite, _ = fl.GetBool("overwrite")
	f.verify, _ = fl.GetBool("verify")
	f.idleTimeout, _ = fl.GetDuration("idle-timeout")
	f.noMDNS, _ = fl.GetBool("no-mdns")
	var err error
	if f.noSweep, f.sweepPort, err = sweepFlagsFrom(fl); err != nil {
		return nil, err
	}
	switch len(args) {
	case 0:
		f.dest = "."
	case 1:
		f.dest = args[0]
	default:
		return nil, usagef("receive takes at most one destination directory, got %d arguments", len(args))
	}
	if f.port < 0 || f.port > 65535 {
		return nil, usagef("--port must be between 0 and 65535")
	}
	if f.idleTimeout < 0 {
		return nil, usagef("--idle-timeout must not be negative")
	}
	return f, nil
}

func runReceive(ctx context.Context, f *receiveFlags, verbose int, env *environment) int {
	prog := newProgress(env)
	log := newLogger(prog.Writer(), verbose)

	c, err := code.Generate(nil)
	if err != nil {
		printError(env, fail.New(fail.Internal, "cannot generate a code", "", err))
		return fail.ExitInternal
	}
	pairer, err := pairing.NewCodePairer(c)
	if err != nil {
		printError(env, fail.New(fail.Internal, "cannot derive keys", "", err))
		return fail.ExitInternal
	}
	r, err := recv.New(recv.Options{
		Dest: f.dest, Pairer: pairer, Overwrite: f.overwrite, Verify: f.verify,
		IdleTimeout: f.idleTimeout, Logger: log, Progress: prog,
	})
	if err != nil {
		printError(env, err)
		return fail.KindOf(err).ExitCode()
	}
	defer func() { _ = r.Close() }()

	ln, err := net.Listen("tcp", net.JoinHostPort(f.bind, strconv.Itoa(f.port)))
	if err != nil {
		printError(env, fail.New(fail.Network, "cannot listen on "+net.JoinHostPort(f.bind, strconv.Itoa(f.port)),
			"choose another --port, or check --bind", err))
		return fail.ExitNetwork
	}
	port := ln.Addr().(*net.TCPAddr).Port

	// RCV-2: the banner on stdout has a stable, documented format that
	// scripts and the end-to-end tests parse:
	//   Listening on HOST:PORT     (one line per address)
	//   Code: WORD-WORD-...
	// This is the only place the code is ever revealed (CODE-6).
	for _, a := range listenAddrs(f.bind, port) {
		fmt.Fprintf(env.stdout, "Listening on %s\n", a)
	}
	fmt.Fprintf(env.stdout, "Code: %s\n", c.Reveal())
	if fl, ok := env.stdout.(interface{ Sync() error }); ok {
		_ = fl.Sync()
	}
	fmt.Fprintf(env.stderr, "On the sending machine, run: %s send CODE PATH...  (add --to HOST:PORT if it cannot find this receiver)\n", meta.Name)

	d := discovery{mdns: !f.noMDNS, sweep: !f.noSweep, sweepPort: f.sweepPort}
	stopAdv := advertise(ctx, port, pairer.DiscoveryTag(), d, f.bind, log)
	defer stopAdv()

	pctx, stopProg := context.WithCancel(ctx)
	go prog.Run(pctx, 0)
	sum, runErr := r.Run(ctx, ln)
	stopProg()
	printReceiveSummary(env, sum)
	if runErr != nil {
		printError(env, runErr)
	}
	return fail.Worst(fail.KindOf(runErr), sum.Kind()).ExitCode()
}

// listenAddrs lists the addresses a sender can use (RCV-4): every
// non-loopback unicast address on an up interface, or loopback if that is
// all there is. With an explicit --bind, only that address.
func listenAddrs(bind string, port int) []string {
	p := strconv.Itoa(port)
	if ip := net.ParseIP(bind); bind != "" && (ip == nil || !ip.IsUnspecified()) {
		return []string{net.JoinHostPort(bind, p)}
	}
	var out, loop []string
	ifaces, _ := net.Interfaces()
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipn.IP
			switch {
			case ip.IsLoopback():
				loop = append(loop, net.JoinHostPort(ip.String(), p))
			case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
				// Link-local IPv6 needs a zone the sender cannot know.
			case ip.To4() == nil && bind == "0.0.0.0":
			default:
				out = append(out, net.JoinHostPort(ip.String(), p))
			}
		}
	}
	if len(out) == 0 {
		if len(loop) == 0 {
			loop = []string{net.JoinHostPort("127.0.0.1", p)}
		}
		return loop[:1]
	}
	return out
}

func printReceiveSummary(env *environment, s *recv.Summary) {
	if s == nil {
		return
	}
	w := env.stderr
	fmt.Fprintf(w, "Summary: %d file(s) received (%s), %d already complete, %d conflict(s), %d error(s), %d integrity failure(s), %d connection(s), %s elapsed\n",
		s.Transferred, bytesText(s.Bytes), s.Skipped, len(s.Conflicts), len(s.Errors), len(s.Integrity), s.Connections, durText(s.Elapsed))
	list(w, "Conflicts (existing files differ; use --overwrite to replace)", s.Conflicts)
	var errs []string
	for _, e := range s.Errors {
		errs = append(errs, proto.Printable(e.Path)+": "+e.Code.String())
	}
	list(w, "Errors", errs)
	list(w, "Integrity failures (hash mismatch after retransmission)", s.Integrity)
	list(w, "Partial files not part of this transfer (left untouched)", s.StrayParts)
	list(w, "Not received yet (rerun the sender to resume)", s.NotTransferred)
}

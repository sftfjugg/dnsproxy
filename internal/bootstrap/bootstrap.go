package bootstrap

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"time"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil"
)

// DialHandler is a dial function for creating unencrypted network connections
// to the upstream server.  It establishes the connection to the server
// specified at initialization and ignores the addr.
type DialHandler func(ctx context.Context, network, addr string) (conn net.Conn, err error)

func ResolveDialContext(
	u *url.URL,
	timeout time.Duration,
	resolvers []Resolver,
) (h DialHandler, err error) {
	host, port, err := netutil.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	var ctx context.Context
	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	} else {
		ctx = context.Background()
	}

	addrs, err := LookupParallel(ctx, resolvers, host)
	if err != nil {
		return nil, err
	}

	var resolverAddresses []string
	for _, addr := range addrs {
		addrPort := netip.AddrPortFrom(addr, uint16(port))
		resolverAddresses = append(resolverAddresses, addrPort.String())
	}

	return NewDialContext(timeout, resolverAddresses...), nil
}

func NewDialContext(timeout time.Duration, addrs ...string) (h DialHandler) {
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	if len(addrs) == 0 {
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.Error("no addresses")
		}
	}

	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		var errs []error

		// Return first connection without error.
		//
		// Note that we're using addrs instead of what's passed to the function.
		for _, addr := range addrs {
			log.Tracef("Dialing to %s", addr)
			start := time.Now()
			conn, err := dialer.DialContext(ctx, network, addr)
			elapsed := time.Since(start)
			if err == nil {
				log.Tracef(
					"dialer has successfully initialized connection to %s in %s",
					addr,
					elapsed,
				)

				return conn, nil
			}

			errs = append(errs, err)

			log.Tracef(
				"dialer failed to initialize connection to %s, in %s, cause: %s",
				addr,
				elapsed,
				err,
			)
		}

		return nil, errors.List("all dialers failed", errs...)
	}
}

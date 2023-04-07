package upstream

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	proxynetutil "github.com/AdguardTeam/dnsproxy/internal/netutil"
	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

type upstreamResolver struct {
	ups Upstream
}

// NewResolver creates an instance of a Resolver structure with defined net.Resolver and it's address
// resolverAddress -- is address of net.Resolver
// The host in the address parameter of Dial func will always be a literal IP address (from documentation)
// options are the upstream customization options, nil means use default
// options.
func NewResolver(resolverAddress string, options *Options) (Resolver, error) {
	if resolverAddress == "" {
		return &net.Resolver{}, nil
	}

	if options == nil {
		options = &Options{}
	}

	var err error
	opts := &Options{
		Timeout:                 options.Timeout,
		VerifyServerCertificate: options.VerifyServerCertificate,
	}

	ur := upstreamResolver{}
	ur.ups, err = AddressToUpstream(resolverAddress, opts)
	if err != nil {
		log.Error("AddressToUpstream: %s", err)

		return ur, fmt.Errorf("AddressToUpstream: %s", err)
	}

	// Validate the bootstrap resolver. It must be either a plain DNS resolver.
	// Or a DoT/DoH resolver with an IP address (not a hostname).
	if !isResolverValidBootstrap(ur.ups) {
		ur.ups = nil
		log.Error("Resolver %s is not eligible to be a bootstrap DNS server", resolverAddress)

		return ur, fmt.Errorf("Resolver %s is not eligible to be a bootstrap DNS server", resolverAddress)
	}

	return ur, nil
}

// isResolverValidBootstrap checks if the upstream is eligible to be a bootstrap
// DNS server DNSCrypt and plain DNS resolvers are okay DoH and DoT are okay
// only in the case if an IP address is used in the IP address.
func isResolverValidBootstrap(upstream Upstream) bool {
	if u, ok := upstream.(*dnsOverTLS); ok {
		urlAddr, err := url.Parse(u.Address())
		if err != nil {
			return false
		}
		host, _, err := net.SplitHostPort(urlAddr.Host)
		if err != nil {
			return false
		}

		if ip := net.ParseIP(host); ip != nil {
			return true
		}
		return false
	}

	if u, ok := upstream.(*dnsOverHTTPS); ok {
		urlAddr, err := url.Parse(u.Address())
		if err != nil {
			return false
		}
		host, _, err := net.SplitHostPort(urlAddr.Host)
		if err != nil {
			host = urlAddr.Host
		}

		if ip := net.ParseIP(host); ip != nil {
			return true
		}
		return false
	}

	a := upstream.Address()
	if strings.HasPrefix(a, "sdns://") {
		return true
	}

	a = strings.TrimPrefix(a, "tcp://")

	host, _, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)

	return ip != nil
}

type resultError struct {
	resp *dns.Msg
	err  error
}

func (r upstreamResolver) resolve(host string, qtype uint16, ch chan *resultError) {
	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			RecursionDesired: true,
		},
		Question: []dns.Question{{
			Name:   host,
			Qtype:  qtype,
			Qclass: dns.ClassINET,
		}},
	}

	resp, err := r.ups.Exchange(req)
	ch <- &resultError{resp, err}
}

// LookupNetIP implements the [Resolver] interface for upstreamResolver.
//
// TODO(e.burkov):  !! sort results of usages
func (r upstreamResolver) LookupNetIP(
	ctx context.Context,
	network string,
	host string,
) (ipAddrs []netip.Addr, err error) {
	// TODO(e.burkov):  Investigate when r.ups is nil and why.
	if r.ups == nil || host == "" {
		return []netip.Addr{}, nil
	}

	if host[:1] != "." {
		host += "."
	}

	var resCh chan *resultError
	n := 1
	switch network {
	case "ip4":
		resCh = make(chan *resultError, n)

		go r.resolve(host, dns.TypeA, resCh)
	case "ip6":
		resCh = make(chan *resultError, n)

		go r.resolve(host, dns.TypeAAAA, resCh)
	case "ip":
		n = 2
		resCh = make(chan *resultError, n)

		go r.resolve(host, dns.TypeA, resCh)
		go r.resolve(host, dns.TypeAAAA, resCh)
	default:
		return []netip.Addr{}, fmt.Errorf("unsupported network: %s", network)
	}

	var errs []error
	for ; n > 0; n-- {
		re := <-resCh
		if re.err != nil {
			errs = append(errs, re.err)

			continue
		}

		for _, rr := range re.resp.Answer {
			if addr, ok := netip.AddrFromSlice(proxyutil.IPFromRR(rr)); ok {
				ipAddrs = append(ipAddrs, addr)
			}
		}
	}

	if len(ipAddrs) == 0 && len(errs) > 0 {
		return []netip.Addr{}, errs[0]
	}

	// Use the previous dnsproxy behavior: prefer IPv4 by default.
	//
	// TODO(a.garipov): Consider unexporting this entire method or documenting
	// that the order of addrs is undefined.
	proxynetutil.SortNetIPAddrs(ipAddrs, false)

	return ipAddrs, nil
}

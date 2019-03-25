package discovery

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wish/discovery/resolver"
)

func RunLocalUDPServer(laddr string) (*dns.Server, string, error) {
	pc, err := net.ListenPacket("udp", laddr)
	if err != nil {
		return nil, "", err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	go func() {
		server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), nil
}

func TestDiscovery(t *testing.T) {
	tests := []struct {
		q   string
		r   []ServiceAddress
		err bool
	}{
		// Query with IP, we expect that same IP back
		{
			q: "127.0.0.1",
			r: []ServiceAddress{ServiceAddress{
				Name:     "127.0.0.1",
				IP:       net.ParseIP("127.0.0.1"),
				isStatic: true,
			}},
		},
		// Query with IP+port, expect back IP+port
		{
			q: "127.0.0.1:1234",
			r: []ServiceAddress{ServiceAddress{
				Name:     "127.0.0.1",
				IP:       net.ParseIP("127.0.0.1"),
				Port:     1234,
				isStatic: true,
			}},
		},
		// Just a name, no port
		{
			q: "example.com",
			r: []ServiceAddress{ServiceAddress{
				Name: "1.2.3.4",
				IP:   net.ParseIP("1.2.3.4"),
			}},
		},
		// SRV response
		{
			q: "srv.com",
			r: []ServiceAddress{ServiceAddress{
				Name: "example.com",
				IP:   net.ParseIP("1.2.3.4"),
				Port: 5060,
			}},
		},
		// SRV with a port-- since SRV exists the port won't match
		{
			q: "srv.com:80",
			r: []ServiceAddress{ServiceAddress{
				Name: "example.com",
				IP:   net.ParseIP("1.2.3.4"),
				Port: 5060,
			}},
		},
		// ipv6 destination
		{
			q: "v6.com",
			r: []ServiceAddress{ServiceAddress{
				Name: "::102:304",
				IP:   net.ParseIP("::1.2.3.4"),
			}},
		},

		// SRV ipv6 response
		{
			q: "srvV6.com",
			r: []ServiceAddress{ServiceAddress{
				Name: "v6.com",
				IP:   net.ParseIP("::1.2.3.4"),
				Port: 5060,
			}},
		},
		// SRV ipv6 a port-- since SRV exists the port won't match
		{
			q: "srvV6.com:80",
			r: []ServiceAddress{ServiceAddress{
				Name: "v6.com",
				IP:   net.ParseIP("::1.2.3.4"),
				Port: 5060,
			}},
		},
	}

	zones := map[string]string{
		"example.com.": "example.com. 1 IN A 1.2.3.4",
		"v6.com.":      "example.com. 1 IN AAAA ::1.2.3.4",
		"srv.com.":     "srv.com. 1 IN    SRV 0       0     5060 example.com.\nsrv.com. 600 IN A 1.2.3.4",
		"srvV6.com.":   "srv.com. 1 IN    SRV 0       0     5060 v6.com.\nsrv.com. 600 IN AAAA ::1.2.3.4",
	}

	// Start DNS server
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(req)
		msg.Authoritative = true
		domain := msg.Question[0].Name
		zoneStr, ok := zones[domain]
		if ok {
			parser := dns.NewZoneParser(strings.NewReader(zoneStr), domain, "")
			for {
				rr, ok := parser.Next()
				if !ok {
					break
				}
				if rr.Header().Rrtype == req.Question[0].Qtype {
					msg.Answer = append(msg.Answer, rr)
				}
			}
		}
		w.WriteMsg(&msg)
	})
	defer dns.HandleRemove(".")

	s, addrstr, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	_, port, err := net.SplitHostPort(addrstr)
	if err != nil {
		t.Fatal(err)
	}

	r := resolver.NewResolverFromConfig(&dns.ClientConfig{
		Servers: []string{"127.0.0.1"},
		Port:    port,
	})

	d := discovery{c: DefaultConfig, r: r}

	ctx := context.TODO()

	for i, test := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			addrs, err := d.GetServiceAddresses(ctx, test.q)
			if (err != nil) != test.err {
				t.Fatalf("Wrong error, err=%v expectedErr=%v", err, test.err)
			}

			// Hack to avoid creating separate comparator
			for x, a := range addrs {
				test.r[x].expiresAt = a.expiresAt
			}

			if !ServiceAddresses(test.r).Equal(addrs) {
				t.Fatalf("Mismatch in addrs \nexpected=%v \nactual=%v", test.r, addrs)
			}
		})
	}
}

func TestDiscoverySubscribe(t *testing.T) {
	zones := map[string]string{
		"example.com.": "example.com. 1 IN A 1.2.3.4",
	}

	// Start DNS server
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		msg := dns.Msg{}
		msg.SetReply(req)
		msg.Authoritative = true
		domain := msg.Question[0].Name
		zoneStr, ok := zones[domain]
		if ok {
			parser := dns.NewZoneParser(strings.NewReader(zoneStr), domain, "")
			for {
				rr, ok := parser.Next()
				if !ok {
					break
				}
				if rr.Header().Rrtype == req.Question[0].Qtype {
					msg.Answer = append(msg.Answer, rr)
				}
			}
		}
		w.WriteMsg(&msg)
	})
	defer dns.HandleRemove(".")

	s, addrstr, err := RunLocalUDPServer(":0")
	if err != nil {
		t.Fatalf("unable to run test server: %v", err)
	}
	defer s.Shutdown()

	_, port, err := net.SplitHostPort(addrstr)
	if err != nil {
		t.Fatal(err)
	}

	r := resolver.NewResolverFromConfig(&dns.ClientConfig{
		Servers: []string{"127.0.0.1"},
		Port:    port,
	})

	d := discovery{c: DefaultConfig, r: r}

	ctx := context.TODO()

	var cbAddrs ServiceAddresses
	var cbErr error
	cbCh := make(chan struct{})
	cb := func(_ context.Context, addrs ServiceAddresses) error {
		select {
		case cbCh <- struct{}{}:
		default:
		}
		cbAddrs = addrs
		return cbErr
	}

	// Do a subscribe
	if err := d.SubscribeServiceAddresses(ctx, "example.com", cb); err != nil {
		t.Fatalf("Error doing initial subscribe: %v", err)
	}

	// wait a second, ensure that we got another
	select {
	case <-cbCh:
	case <-time.After(time.Second * 2):
		t.Fatalf("CB failed")
	}

	// set an error, ensure that we get some more retires
	cbErr = fmt.Errorf("some error")
	prevAddrs := cbAddrs
	for i := 0; i < 3; i++ {
		select {
		case <-cbCh:
		case <-time.After(time.Second * 2):
			t.Fatalf("CB failed")
		}
	}

	// Clear error ensure that we get an update
	cbErr = nil
	select {
	case <-cbCh:
	case <-time.After(time.Second * 2):
		t.Fatalf("CB failed")
	}

	if cbAddrs.Equal(prevAddrs) {
		t.Fatalf("no update!")
	}
}

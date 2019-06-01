package lib

import (
	"context"
	"log"
	"net"
	"net/smtp"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

func getDialer(cfg *Config) proxy.ContextDialer {
	if cfg.DialerProxy != "" {
		url, err := url.Parse(cfg.DialerProxy)
		if err != nil {
			log.Fatal(err)
		}
		d, err := proxy.FromURL(url, nil)
		if err != nil {
			log.Fatal(err)
		}

		p, ok := d.(proxy.ContextDialer)
		if !ok {
			log.Fatal("Parsed Proxy doesn't support context")
		}
		return p
	} else {
		return &net.Dialer{}
	}
}

func FindServers(domain string, cfg *Config) []string {
	resolver := net.Resolver{
		PreferGo: true,
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
	mxs, err := resolver.LookupMX(ctx, domain)
	cancel()
	if err != nil {
		if dnserr, ok := err.(*net.DNSError); !ok || dnserr.Err != "no such host" {
			log.Fatal(err)
		}
	}
	if len(mxs) > 0 {
		hosts := make([]string, len(mxs))
		for i, mx := range mxs {
			hosts[i] = mx.Host
		}
		return hosts
	} else {
		// fall back to a record.
		return []string{domain}
	}
}

func DialFromList(hosts []string, cfg *Config) (*smtp.Client, string) {
	dialer := getDialer(cfg)

	for _, host := range hosts {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
		conn, err := dialer.DialContext(ctx, "tcp", host+":smtp")
		cancel()
		if err == nil {
			c, err := smtp.NewClient(conn, host)
			if err == nil {
				return c, host
			}
		}
	}

	// fall back to 587 - mail submission port
	for _, host := range hosts {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Second))
		conn, err := dialer.DialContext(ctx, "tcp", host+":587")
		cancel()
		if err == nil {
			c, err := smtp.NewClient(conn, host)
			if err == nil {
				return c, host
			}
		}
	}

	log.Fatal("Unable to connect to any mail server")
	return nil, ""
}

func StartTLS(conn *smtp.Client, serverName string, cfg *Config) {
	tlsCfg := cfg.GetTLS()
	tlsCfg.ServerName = serverName
	err := conn.StartTLS(tlsCfg)
	if err != nil {
		log.Fatalf("Failed to secure sending: %v", err)
	}
}

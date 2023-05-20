package caddyrl

import (
	"fmt"
	"net"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/geoip2-golang"
)

type Rule struct {
	// true means allow and false means deny
	Action     bool     `json:"action"`
	CidrFilter []string `json:"cidr,omitempty"`
	// Country and City are ISO 3166-1
	City    []string `json:"city,omitempty"`
	Country []string `json:"country,omitempty"`
	cidr    []*net.IPNet
}

// RateLimit describes an HTTP rate limit zone.
type RateLimit struct {
	// Request matchers, which defines the class of requests that are in the RL zone.
	MatcherSetsRaw caddyhttp.RawMatcherSets `json:"match,omitempty" caddy:"namespace=http.matchers"`

	// The key which uniquely differentiates rate limits within this zone. It could
	// be a static string (no placeholders), resulting in one and only one rate limiter
	// for the whole zone. Or, placeholders could be used to dynamically allocate
	// rate limiters. For example, a key of "foo" will create exactly one rate limiter
	// for all clients. But a key of "{http.request.remote.host}" will create one rate
	// limiter for each different client IP address.
	// Key string `json:"key,omitempty"`

	// Number of events allowed within the window.
	MaxEvents int `json:"max_events,omitempty"`

	// Duration of the sliding window.
	Window caddy.Duration `json:"window,omitempty"`

	matcherSets caddyhttp.MatcherSets

	zoneName string

}

func (rl *RateLimit) provision(ctx caddy.Context, name string) error {
	if rl.Window <= 0 {
		return fmt.Errorf("window must be greater than zero")
	}
	if rl.MaxEvents < 0 {
		return fmt.Errorf("max_events must be at least zero")
	}

	if len(rl.MatcherSetsRaw) > 0 {
		matcherSets, err := ctx.LoadModule(rl, "MatcherSetsRaw")
		if err != nil {
			return err
		}
		err = rl.matcherSets.FromInterface(matcherSets)
		if err != nil {
			return err
		}
	}



	return nil
}

func (rl *RateLimit) permissiveness() float64 {
	return float64(rl.MaxEvents) / float64(rl.Window)
}

func (r *Rule) provision() error {
	for _, cidr_str := range r.CidrFilter {
		_, cidr, err := net.ParseCIDR(cidr_str)
		if err != nil {
			return err
		}
		r.cidr = append(r.cidr, cidr)
	}
	return nil
}

func (r *Rule) match(ip net.IP, geoip *geoip2.Reader) bool {
	for _, cidr := range r.cidr {
		if cidr.Contains(ip) {
			return true
		}
	}
	if geoip == nil {
		return false
	}
	if len(r.City) != 0 || len(r.Country) != 0 {
		city, err := geoip.City(ip)
		if err != nil {
			if len(r.Country) != 0 && Contains(r.Country, city.Country.IsoCode) {
				return true
			}
			if len(r.City) != 0 && Contains(r.City, city.City.Names["zh-CN"]) {
				return true
			}
		}
	}
	return false
}

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

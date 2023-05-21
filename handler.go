package caddyrl

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	redsyncredis "github.com/go-redsync/redsync/v4/redis"
	"github.com/go-redsync/redsync/v4/redis/goredis/v9"
	"github.com/mennanov/limiters"
	"github.com/oschwald/geoip2-golang"
	goredislib "github.com/redis/go-redis/v9"
	_ "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements rate limiting functionality.
//
// If a rate limit is exceeded, an HTTP error with status 429 will be
// returned. This error can be handled using the conventional error
// handling routes in your config. An additional placeholder is made
// available, called `{http.rate_limit.exceeded.name}`, which you can
// use for logging or handling; it contains the name of the rate limit
// zone which limit was exceeded.
type Handler struct {
	// RateLimits contains the definitions of the rate limit zones, keyed by name.
	// The name **MUST** be globally unique across all other instances of this handler.
	RateLimits map[string]*RateLimit `json:"rate_limits,omitempty"`

	// Enables distributed rate limiting. For this to work properly, rate limit
	// zones must have the same configuration for all instances in the cluster
	// because an instance's own configuration is used to calculate whether a
	// rate limit is exceeded. As usual, a cluster is defined to be all instances
	// sharing the same storage configuration.

	// Storage backend through which rate limit state is synced. If not set,
	// the global or default storage configuration will be used.
	StorageRaw json.RawMessage `json:"storage,omitempty" caddy:"namespace=caddy.storage inline_key=module"`
	Redis      struct {
		Addr     string `json:"addr,omitempty"`
		Password string `json:"password,omitempty"`
		DB       int    `json:"db,omitempty"`
	} `json:"redis,omitempty"`
	GeoIpPath string  `json:"geoip,omitempty"`
	Rules     []*Rule `json:"rules,omitempty"`

	rateLimits  []*RateLimit
	geoip       *geoip2.Reader
	logger      *zap.Logger
	redisClient *goredislib.Client
	pool        redsyncredis.Pool
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.rate_limit",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	if h.GeoIpPath != "" {
		db, err := geoip2.Open(h.GeoIpPath)
		if err != nil {
			return fmt.Errorf("opening geoip database: %v", err)
		}
		h.geoip = db
	}
	for _, r := range h.Rules {
		if err := r.provision(); err != nil {
			return err
		}
	}

	h.redisClient = goredislib.NewClient(&goredislib.Options{
		Addr:     h.Redis.Addr,
		Password: h.Redis.Password,
		DB:       h.Redis.DB})
	h.pool = goredis.NewPool(h.redisClient)
	_, err := h.redisClient.Ping(ctx.Context).Result()
	if err != nil {
		return fmt.Errorf("redis ping: %v", err)
	}
	clock := limiters.NewSystemClock()

	// provision each rate limit and put them in a slice so we can sort them
	for name, rl := range h.RateLimits {
		rl.zoneName = name
		err := rl.provision(ctx, name)
		if err != nil {
			return fmt.Errorf("setting up rate limit %s: %v", name, err)
		}
		h.rateLimits = append(h.rateLimits, rl)
	}

	// sort by tightest rate limit to most permissive (issue #10)
	sort.Slice(h.rateLimits, func(i, j int) bool {
		return h.rateLimits[i].permissiveness() > h.rateLimits[j].permissiveness()
	})

	go func() {
		// Garbage collect the old limiters to prevent memory leaks.
		for {
			<-time.After(time.Duration(10 * time.Second))
			registry.DeleteExpired(clock.Now())
		}
	}()
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip_str, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(ip_str)
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for _, rule := range h.Rules {
		if rule.match(ip, h.geoip) {
			if rule.Action {
				return next.ServeHTTP(w, r)
			} else {
				h.logger.Warn("unallow access from region", zap.String("ip", ip_str))
				return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("your IP address is not allowed to access this site"))
			}
		}
	}

	// iterate the slice, not the map, so the order is deterministic
	for _, rl := range h.rateLimits {
		// ignore rate limit if request doesn't qualify
		if !rl.matcherSets.AnyMatch(r) {
			continue
		}
		logger := limiters.NewStdLogger()
		bucket := registry.GetOrCreate(ip_str, func() interface{} {
			return limiters.NewTokenBucket(
				5,
				time.Duration(rl.Window),
				limiters.NewLockRedis(h.pool, fmt.Sprintf("/l/%s/%s", rl.zoneName, ip)),
				limiters.NewTokenBucketRedis(
					h.redisClient,
					fmt.Sprintf("/r/%s/%s", rl.zoneName, ip),
					time.Duration(rl.Window), true),
				clock, logger)
		}, time.Duration(rl.Window), clock.Now())
		wait, err := bucket.(*limiters.TokenBucket).Limit(r.Context())
		if err == limiters.ErrLimitExhausted {
			h.logger.Warn("rate limit exceeded", zap.String("ip", ip_str))
			return h.rateLimitExceeded(w, repl, rl.zoneName, wait)
		} else if err != nil {
			// The limiter failed. This error should be logged and examined.
			h.logger.Error("limiter failed", zap.Error(err))
			return caddyhttp.Error(http.StatusTooManyRequests, nil)
		}
	}

	return next.ServeHTTP(w, r)
}

func (h *Handler) rateLimitExceeded(w http.ResponseWriter, repl *caddy.Replacer, zoneName string, wait time.Duration) error {
	// add 0.5 to ceil() instead of round() which FormatFloat() does automatically
	w.Header().Set("Retry-After", strconv.FormatFloat(wait.Seconds()+0.5, 'f', 0, 64))

	// make some information about this rate limit available
	repl.Set("http.rate_limit.exceeded.name", zoneName)

	return caddyhttp.Error(http.StatusTooManyRequests, nil)
}

// Cleanup cleans up the handler.
func (h *Handler) Cleanup() error {
	// remove unused rate limit zones
	for name := range h.RateLimits {
		rateLimits.Delete(name)
	}
	return nil
}

// rateLimits persists RL zones through config changes.
var rateLimits = caddy.NewUsagePool()
var registry = limiters.NewRegistry()
var clock = limiters.NewSystemClock()

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddy.CleanerUpper          = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

// Copyright 2021 Matthew Holt

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyrl

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevents"
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
	Redis struct {
		Addr     string `json:"addr,omitempty"`
		Password string `json:"password,omitempty"`
		DB       int    `json:"db,omitempty"`
	} `json:"redis,omitempty"`
	GeoIpPath   string  `json:"geoip,omitempty"`
	Rules       []*Rule `json:"rules,omitempty"`
	Relocation  string  `json:"relocation,omitempty"`
	rateLimits  []*RateLimit
	geoip       *geoip2.Reader
	logger      *zap.Logger
	redisClient *goredislib.Client
	pool        redsyncredis.Pool
	ctx         caddy.Context
	events      *caddyevents.App
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
	h.ctx = ctx
	h.logger = ctx.Logger(h)

	eventsAppIface, err := ctx.App("events")
	if err != nil {
		return fmt.Errorf("getting events app: %v", err)
	}
	h.events = eventsAppIface.(*caddyevents.App)

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
	_, err = h.redisClient.Ping(ctx.Context).Result()
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
			select {
			case <-ctx.Context.Done():
				return
			case <-time.After(time.Duration(10 * time.Second)):
				registry.DeleteExpired(clock.Now())
			}
		}
	}()
	return nil
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip_str, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(ip_str)

	if r.Method == http.MethodPost && r.URL.Path == "/unblock_ip" {
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			http.Error(w, "IP parameter is missing", http.StatusBadRequest)
			return nil
		}
		err := h.UnblockIP(ip)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("IP unblocked successfully"))
		return nil
	}

	if r.Method == http.MethodPost && r.URL.Path == "/set_ban_duration" {
		ip := r.URL.Query().Get("ip")
		durationStr := r.URL.Query().Get("duration")
		if ip == "" || durationStr == "" {
			http.Error(w, "IP or duration parameter is missing", http.StatusBadRequest)
			return nil
		}

		duration, err := time.ParseDuration(durationStr + "s")
		if err != nil {
			http.Error(w, "Invalid duration format", http.StatusBadRequest)
			return nil
		}

		err = h.setBanDuration(ip, duration)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return nil
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ban duration set successfully"))
		return nil
	}

	for _, rule := range h.Rules {
		if rule.match(ip, h.geoip) {
			if rule.Action {
				h.logger.Debug("allow access from region", zap.Int("type", 0), zap.String("ip", ip_str), zap.String("zone", h.rateLimits[0].zoneName))
				return next.ServeHTTP(w, r)
			} else {
				h.logger.Warn("unallow access from region", zap.Int("type", 1), zap.String("ip", ip_str), zap.String("zone", h.rateLimits[0].zoneName))
				return h.rateLimitExceeded(w, h.rateLimits[0].zoneName, h.rateLimits[0].Window, ip_str)
			}
		}
	}

	// iterate the slice, not the map, so the order is deterministic
	logger := limiters.NewStdLogger()
	for _, rl := range h.rateLimits {
		if !rl.matcherSets.AnyMatch(r) {
			continue
		}
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
		_, err := bucket.(*limiters.TokenBucket).Limit(r.Context())
		if err == limiters.ErrLimitExhausted {
			if rl.BanDuration > 0 {
				banKey := fmt.Sprintf("/banned/%s", ip_str)
				err := h.redisClient.Set(r.Context(), banKey, "banned", time.Duration(rl.BanDuration)).Err()
				if err != nil {
					h.logger.Error("failed to set ban duration", zap.String("ip", ip_str), zap.Error(err))
				}
			}
			h.logger.Warn("rate limit exceeded", zap.Int("type", 2), zap.String("ip", ip_str), zap.String("zone", rl.zoneName))
			return h.rateLimitExceeded(w, rl.zoneName, rl.Window, ip_str)
		} else if err != nil {
			return caddyhttp.Error(http.StatusTooManyRequests, nil)
		}
	}

	return next.ServeHTTP(w, r)
}

func (h *Handler) rateLimitExceeded(w http.ResponseWriter, zoneName string, wait caddy.Duration, ip string) error {
	h.events.Emit(h.ctx, "rate_limit_exceeded", map[string]any{
		"zone":      zoneName,
		"wait":      wait,
		"remote_ip": ip,
	})
	logger := h.logger.With(
		zap.String("zone", zoneName),
		zap.Duration("wait", time.Duration(wait)),
		zap.String("remote_ip", ip),
	)
	logger.Info("rate limit exceeded")
	if h.Relocation != "" {
		w.Header().Set("Location", h.Relocation)
		return caddyhttp.Error(http.StatusTemporaryRedirect, nil)
	} else {
		return caddyhttp.Error(http.StatusTooManyRequests, nil)
	}
}
func (h *Handler) UnblockIP(ip string) error {
	exists := registry.Exists(ip)
	if !exists {
		h.logger.Warn("IP not found in registry", zap.String("ip", ip))
		return fmt.Errorf("IP %s not found", ip)
	}
	registry.Delete(ip)
	h.logger.Info("unblocked IP", zap.String("ip", ip))
	return nil
}

func (h *Handler) setBanDuration(ip string, duration time.Duration) error {
	banKey := fmt.Sprintf("/banned/%s", ip)
	err := h.redisClient.Set(context.Background(), banKey, "banned", duration).Err()
	if err != nil {
		h.logger.Error("failed to set ban duration", zap.String("ip", ip), zap.Error(err))
		return err
	}
	h.logger.Info("ban duration set", zap.String("ip", ip), zap.Duration("duration", duration))
	return nil
}

// Cleanup cleans up the handler.
func (h *Handler) Cleanup() error {
	// remove unused rate limit zones
	for name := range h.RateLimits {
		rateLimits.Delete(name)
	}
	h.redisClient.Close()
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

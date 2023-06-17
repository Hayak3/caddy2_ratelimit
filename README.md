Caddy HTTP Rate Limit Module
============================

This module implements both internal and distributed HTTP rate limiting. Requests can be rejected after a specified rate limit is hit.



## Features

- Multiple rate limit zones
- IP white list and black list,support cidr
- RL state persisted through config reloads or restart with redis
- Distributed rate limiting across a cluster
- disallow access from some country with geoip

**PLANNED:**

- caddyfile support
- other storage support
- api for unblock banned ip
- choice for ratelimit algorithm

## Building

To build Caddy with this module, use [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
$ xcaddy build --with github.com/hayak3/caddy-ratelimit
```


## Overview

The `rate_limit` HTTP handler module lets you define rate limit zones, which have a unique name of your choosing. A rate limit zone is 1:1 with a rate limit (i.e. events per duration).

A zone also has a key, which is different from its name. Keys associate 1:1 with rate limiters, implemented as ring buffers; i.e. a new key implies allocating a new ring buffer. Keys can be static (no placeholders; same for every request), in which case only one rate limiter will be allocated for the whole zone. Or, keys can contain placeholders which can be different for every request, in which case a zone may contain numerous rate limiters depending on the result of expanding the key.

A zone is synomymous with a rate limit, being a number of events per duration. Both `window` and `max_events` are required configuration for a zone. For example: 100 events every 1 minute. Because this module uses a sliding window algorithm, it works by looking back `<window>` duration and seeing if `<max_events>` events have already happened in that timeframe. If so, an internal HTTP 429 error is generated and returned, invoking error routes which you have defined (if any). Otherwise, the a reservation is made and the event is allowed through.

Each zone may optionally filter the requests it applies to by specifying [request matchers](https://caddyserver.com/docs/modules/http#servers/routes/match).

Unlike nginx's rate limit module, this one does not require you to set a memory bound. Instead, rate limiters are scanned every so often and expired ones are deleted so their memory can be recovered by the garbage collector: Caddy does not drop rate limiters on the floor and forget events like nginx does.

### Distributed rate limiting

We storage the ratelimit status and ip blocked in redis,you can only manually unblock in redis,here is an example.
just delete the key "/r/{zonename}/{ip}" in redis

## Syntax

This is an HTTP handler module, so it can be used wherever `http.handlers` modules are accepted.

### JSON config

```json
{
	"handler": "rate_limit",
	"rate_limits": {
		"<name>": {
			"match": [],
			"key": "",
			"window": "",
			"max_events": 0
		},
		"distributed": {
			"write_interval": "",
			"read_interval": ""
		},
		"rules": [
			{
				"action": true,
				"cidr": ["192.168.0.0/24"]
			},
			{
				"action": true,
				"city": ["杭州"],
				"country": ["CN"]
			}
		],
		"geoip": "the geoip file"
	}
}
```


### JSON example

```json
{
	"apps": {
		"http": {
			"servers": {
				"demo": {
					"listen": [":80"],
					"routes": [
						{
							"handle": [
								{
									"handler": "rate_limit",
									"rate_limits": {
										"static_example": {
											"match": [
												{"method": ["GET"]}
											],
											"key": "static",
											"window": "1m",
											"max_events": 100
										},
										"dynamic_example": {
											"key": "{http.request.remote.host}",
											"window": "5s",
											"max_events": 2
										}
									},
									"distributed": {},
									"rules": [
										{
											"action": true,
											"cidr": ["192.168.0.0/24"]
										},
										{
											"action": true,
											"city": ["杭州"],
											"country": ["CN"]
										}
									],
									"geoip": "./GeoLite2-City.mmdb"
								},
								{
									"handler": "static_response",
									"body": "I'm behind the rate limiter!"
								}
							]
						}
					]
				}
			}
		}
	}
}
```


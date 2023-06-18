Caddy HTTP Rate Limit Module(This is a fork of https://github.com/mholt/caddy-ratelimit)
============================

This module implements both internal and distributed HTTP rate limiting. Requests can be rejected after a specified rate limit is hit.



## Features

- Multiple rate limit zones
- IP white list and black list,support cidr
- RL state persisted through config reloads or restart with redis
- Distributed rate limiting across a cluster
- disallow access from some country with geoip

**PLANNED:**

- other storage support
- api for unblock banned ip
- choice for ratelimit algorithm

## Building

To build Caddy with this module, use [xcaddy](https://github.com/caddyserver/xcaddy):

```bash
$ xcaddy build --with github.com/hayak3/caddy-ratelimit
```


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
### CaddyFile example
```
http://example.com {
	rate_limit {
		zone static_example {
			max_events 100
			window 1m
		}
		zone dynamic_example {
			max_events 2
			window 5s
		}
		redis {
			addr 127.0.0.1:6379
			password ""
			db 0
		}
		rule {
			{
				action allow
				cidr "192.168.0.1/32" "192.168.0.0/24"
				city "Paris" "London"
			}
			{
				action deny
				cidr "192.168.1.1/32" "192.168.5.0/24"
				city "Paris" "London"
			}
		}
		geoip ./geoip/GeoLite2-City.mmdb
		relocation example.com
	}
	reverse_proxy * http://127.0.0.1:8080 {
		header_up Host {upstream_hostport}
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


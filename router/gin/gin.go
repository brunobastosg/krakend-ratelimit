package gin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/luraproject/lura/v2/config"
	"github.com/luraproject/lura/v2/logging"
	"github.com/luraproject/lura/v2/proxy"
	krakendgin "github.com/luraproject/lura/v2/router/gin"

	krakendrate "github.com/breathbath/krakend-ratelimit/v3"
	"github.com/breathbath/krakend-ratelimit/v3/router"
)

// HandlerFactory is the out-of-the-box basic ratelimit handler factory using the default krakend endpoint
// handler for the gin router
var HandlerFactory = NewRateLimiterMw(logging.NoOp, krakendgin.EndpointHandler)

// NewRateLimiterMw builds a rate limiting wrapper over the received handler factory.
func NewRateLimiterMw(logger logging.Logger, next krakendgin.HandlerFactory) krakendgin.HandlerFactory {
	return func(remote *config.EndpointConfig, p proxy.Proxy) gin.HandlerFunc {
		logPrefix := "[ENDPOINT: " + remote.Endpoint + "][Ratelimit]"
		handlerFunc := next(remote, p)

		cfg, err := router.ConfigGetter(remote.ExtraConfig)
		if err != nil {
			if err != router.ErrNoExtraCfg {
				logger.Error(logPrefix, err)
			}
			return handlerFunc
		}

		if cfg.MaxRate <= 0 && cfg.ClientMaxRate <= 0 {
			return handlerFunc
		}

		if cfg.MaxRate > 0 {
			if cfg.Capacity == 0 {
				if cfg.MaxRate < 1 {
					cfg.Capacity = 1
				} else {
					cfg.Capacity = uint64(cfg.MaxRate)
				}
			}
			logger.Debug(logPrefix, fmt.Sprintf("Rate limit enabled. MaxRate: %f, Capacity: %d", cfg.MaxRate, cfg.Capacity))
			handlerFunc = NewEndpointRateLimiterMw(krakendrate.NewTokenBucket(cfg.MaxRate, cfg.Capacity))(handlerFunc)
		}

		if cfg.ClientMaxRate > 0 {
			if cfg.ClientCapacity == 0 {
				if cfg.ClientMaxRate < 1 {
					cfg.ClientCapacity = 1
				} else {
					cfg.ClientCapacity = uint64(cfg.ClientMaxRate)
				}
			}
			switch strategy := strings.ToLower(cfg.Strategy); strategy {
			case "ip":
				logger.Debug(logPrefix, fmt.Sprintf("IP-based rate limit enabled. MaxRate: %f, Capacity: %d", cfg.ClientMaxRate, cfg.ClientCapacity))
				handlerFunc = NewIpLimiterWithKeyMwFromCfg(cfg, logger)(handlerFunc)
			case "header":
				logger.Debug(logPrefix, fmt.Sprintf("Header-based rate limit enabled. MaxRate: %f, Capacity: %d", cfg.ClientMaxRate, cfg.ClientCapacity))
				handlerFunc = NewHeaderLimiterMwFromCfg(cfg, logger)(handlerFunc)
			default:
				logger.Warning(logPrefix, "Unknown strategy", strategy)
			}
		}

		return handlerFunc
	}
}

// EndpointMw is a function that decorates the received handlerFunc with some rateliming logic
type EndpointMw func(gin.HandlerFunc) gin.HandlerFunc

// NewEndpointRateLimiterMw creates a simple ratelimiter for a given handlerFunc
func NewEndpointRateLimiterMw(tb *krakendrate.TokenBucket) EndpointMw {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			if !tb.Allow() {
				c.AbortWithError(503, krakendrate.ErrLimited)
				return
			}
			next(c)
		}
	}
}

// NewHeaderLimiterMw creates a token ratelimiter using the value of a header as a token
//
// Deprecated: Use NewHeaderLimiterMwFromCfg instead
func NewHeaderLimiterMw(header string, maxRate float64, capacity uint64, logger logging.Logger) EndpointMw {
	return NewTokenLimiterMw(HeaderTokenExtractor(header), krakendrate.NewMemoryStore(maxRate, int(capacity), logger), logger, 1)
}

// NewHeaderLimiterMwFromCfg creates a token ratelimiter using the value of a header as a token
func NewHeaderLimiterMwFromCfg(cfg router.Config, logger logging.Logger) EndpointMw {
	store := krakendrate.NewLimiterStore(
		cfg.ClientMaxRate,
		int(cfg.ClientCapacity),
		krakendrate.NewShardedMemoryBackend(
			context.Background(),
			krakendrate.DefaultShards,
			cfg.TTL,
			krakendrate.PseudoFNV64a,
		),
		logger,
	)
	logger.Debug("will use token limiter for key ", cfg.Key)
	return NewTokenLimiterMw(HeaderTokenExtractor(cfg.Key), store, logger, cfg.RateFactor)
}

// NewIpLimiterMw creates a token ratelimiter using the IP of the request as a token
func NewIpLimiterMw(maxRate float64, capacity uint64, logger logging.Logger) EndpointMw {
	return NewTokenLimiterMw(IPTokenExtractor, krakendrate.NewMemoryStore(maxRate, int(capacity), logger), logger, 1)
}

// NewIpLimiterWithKeyMw creates a token ratelimiter using the IP of the request as a token
//
// Deprecated: Use NewIpLimiterWithKeyMwFromCfg instead
func NewIpLimiterWithKeyMw(header string, maxRate float64, capacity uint64, logger logging.Logger) EndpointMw {
	if header == "" {
		return NewIpLimiterMw(maxRate, capacity, logger)
	}
	return NewTokenLimiterMw(NewIPTokenExtractor(header), krakendrate.NewMemoryStore(maxRate, int(capacity), logger), logger, 1)
}

// NewIpLimiterWithKeyMwFromCfg creates a token ratelimiter using the IP of the request as a token
func NewIpLimiterWithKeyMwFromCfg(cfg router.Config, logger logging.Logger) EndpointMw {
	store := krakendrate.NewLimiterStore(
		cfg.ClientMaxRate,
		int(cfg.ClientCapacity),
		krakendrate.NewShardedMemoryBackend(
			context.Background(),
			krakendrate.DefaultShards,
			cfg.TTL,
			krakendrate.PseudoFNV64a,
		),
		logger,
	)
	if cfg.Key == "" {
		logger.Debug("will use ip limiter as key is empty")
		return NewTokenLimiterMw(IPTokenExtractor, store, logger, cfg.RateFactor)
	}
	logger.Debug("will use token limiter for key ", cfg.Key)
	return NewTokenLimiterMw(NewIPTokenExtractor(cfg.Key), store, logger, cfg.RateFactor)
}

// TokenExtractor defines the interface of the functions to use in order to extract a token for each request
type TokenExtractor func(*gin.Context) string

// IPTokenExtractor extracts the IP of the request
func IPTokenExtractor(c *gin.Context) string { return c.ClientIP() }

// NewIPTokenExtractor generates an IP TokenExtractor checking first for the contents of the passed header.
// If nothing is found there, the regular IPTokenExtractor function is called.
func NewIPTokenExtractor(header string) TokenExtractor {
	return func(c *gin.Context) string {
		if clientIP := strings.TrimSpace(strings.Split(c.Request.Header.Get(header), ",")[0]); clientIP != "" {
			ip := strings.Split(clientIP, ":")[0]
			if parsedIP := net.ParseIP(ip); parsedIP != nil {
				return ip
			}
		}
		return IPTokenExtractor(c)
	}
}

// HeaderTokenExtractor returns a TokenExtractor that looks for the value of the designed header
func HeaderTokenExtractor(header string) TokenExtractor {
	return func(c *gin.Context) string { return c.Request.Header.Get(header) }
}

const rateLimitHeader = "x-rate-limit"

// NewTokenLimiterMw returns a token based ratelimiting endpoint middleware with the received TokenExtractor and LimiterStore
func NewTokenLimiterMw(tokenExtractor TokenExtractor, limiterStore krakendrate.LimiterStore, logger logging.Logger, rateFactor float64) EndpointMw {
	return func(next gin.HandlerFunc) gin.HandlerFunc {
		return func(c *gin.Context) {
			tokenKey := tokenExtractor(c)

			if tokenKey == "" {
				logger.Error("No token found in headers under the configured key")
				c.AbortWithError(http.StatusTooManyRequests, krakendrate.ErrLimited)
				return
			}

			rateLimitFromHeader := c.Request.Header.Get(rateLimitHeader)

			var maxRate float64
			var capacity int
			if rateLimitFromHeader != "" {
				logger.Debug(fmt.Sprintf("Got rate limit %s", rateLimitFromHeader))
				rateLimitFromHeaderInt, err := strconv.Atoi(rateLimitFromHeader)
				if err == nil {
					capacity = rateLimitFromHeaderInt
					maxRate = float64(rateLimitFromHeaderInt) * rateFactor
					logger.Debug(fmt.Sprintf("Max rate %.2f, capacity %d", maxRate, capacity))
				} else {
					logger.Error("failed to parse rate limit from header", err)
				}
			}

			if !limiterStore(tokenKey, maxRate, capacity).Allow() {
				logger.Error(fmt.Sprintf(
					"rate limit with max rate %.2f and capacity %d for token %s is exceeded",
					maxRate,
					capacity,
					tokenKey,
				))
				c.AbortWithError(http.StatusTooManyRequests, krakendrate.ErrLimited)
				return
			}
			next(c)
		}
	}
}

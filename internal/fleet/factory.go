package fleet

import (
	"net/http"
	"time"

	"github.com/Ju571nK/lodeline-manager/internal/config"
)

// NewFromConfig returns the [Client] selected by the operator's config.
// MOCK_FLEET=1 yields [MockClient]; otherwise an [HTTPClient] pointed at
// LODELINE_SERVER_BASE_URL with the LODELINE_SERVER_READ_TOKEN bearer, presenting
// the configured client certificate when lodeline-server runs mTLS.
//
// Unless FLEET_CACHE_DISABLED=1, the chosen client is wrapped in a
// [CachingClient] so concurrent browser polling collapses onto a steady
// trickle of upstream reads (stale-while-revalidate + single-flight).
func NewFromConfig(cfg *config.Config) Client {
	var base Client
	if cfg.IsMockFleet() {
		base = NewMock(time.Time{})
	} else {
		h := NewHTTPClient(cfg.LodelineServerBaseURL, cfg.LodelineServerReadToken, 0)
		if cfg.LodelineServerTLS != nil {
			t := &http.Transport{Proxy: http.ProxyFromEnvironment}
			if d, ok := http.DefaultTransport.(*http.Transport); ok {
				t = d.Clone()
			}
			t.TLSClientConfig = cfg.LodelineServerTLS
			h.httpClient.Transport = t
		}
		base = h
	}

	if cfg.FleetCacheDisabled {
		return base
	}
	return NewCachingClient(base, cacheConfigFrom(cfg))
}

// cacheConfigFrom derives the cache tuning from operator config. TTL tracks
// the SPA's poll interval (a faster cache than the poll buys nothing); MaxStale
// is a generous multiple so a brief lodeline-server outage degrades to slightly
// old data rather than a blank dashboard.
func cacheConfigFrom(cfg *config.Config) CacheConfig {
	return CacheConfig{
		TTL:        cfg.FleetPollInterval,
		MaxStale:   12 * cfg.FleetPollInterval,
		MaxEntries: cfg.FleetCacheMaxEntries,
	}
}

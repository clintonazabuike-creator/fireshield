package fireshield

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ShieldConfig holds configuration options for Fire Shield
type ShieldConfig struct {
	WindowDuration time.Duration // Time window to track requests (e.g., 10s)
	MaxNormal      int           // Max requests before tarpit starts
}

// DefaultShield returns standard defensive thresholds
func DefaultShield() *ShieldConfig {
	return &ShieldConfig{
		WindowDuration: 10 * time.Second,
		MaxNormal:      3,
	}
}

type IPTracker struct {
	mu       sync.Mutex
	requests map[string][]time.Time
}

var tracker = IPTracker{
	requests: make(map[string][]time.Time),
}

func (t *IPTracker) getDelay(ip string, cfg *ShieldConfig) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-cfg.WindowDuration)

	var recent []time.Time
	for _, reqTime := range t.requests[ip] {
		if reqTime.After(cutoff) {
			recent = append(recent, reqTime)
		}
	}
	recent = append(recent, now)
	t.requests[ip] = recent

	count := len(recent)

	// Escalating tarpit formula
	if count <= cfg.MaxNormal {
		return 0
	} else if count <= cfg.MaxNormal+3 {
		return 3 * time.Second
	} else if count <= cfg.MaxNormal+7 {
		return 7 * time.Second
	} else {
		return 15 * time.Second
	}
}

const verifyHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verifying Connection...</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: #0b0f19; color: #f3f4f6; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem; }
    .card { background: rgba(17, 24, 39, 0.8); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 2rem; max-width: 360px; width: 100%; text-align: center; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); backdrop-filter: blur(8px); }
    .radar { width: 56px; height: 56px; margin: 0 auto 1.25rem; border-radius: 50%; border: 2px solid rgba(16, 185, 129, 0.2); border-top-color: #10b981; animation: spin 1s linear infinite; display: flex; align-items: center; justify-content: center; }
    .shield { width: 24px; height: 24px; fill: #10b981; }
    .title { font-size: 1.1rem; font-weight: 600; color: #f9fafb; margin-bottom: 0.5rem; letter-spacing: -0.01em; }
    .bar-bg { width: 100%; height: 4px; background: rgba(255, 255, 255, 0.1); border-radius: 2px; overflow: hidden; margin: 1.25rem 0 0.75rem; }
    .bar-fill { height: 100%; background: #10b981; width: 0%%; animation: load %ds linear forwards; }
    .brand { font-size: 0.75rem; color: #6b7280; font-weight: 500; }
    .brand span { color: #10b981; font-weight: 600; }
    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes load { to { width: 100%%; } }
  </style>
</head>
<body>
  <div class="card">
    <div class="radar">
      <svg class="shield" viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8s0 0 0 0 z"/></svg>
    </div>
    <div class="title">Verifying connection...</div>
    <div class="bar-bg"><div class="bar-fill"></div></div>
    <div class="brand">Powered by <span>Fire Shield</span></div>
  </div>
  <script>
    setTimeout(function() {
      window.location.reload();
    }, %d);
  </script>
</body>
</html>`

// Protect is the drop-in middleware for any Go developer
func Protect(next http.Handler, cfg *ShieldConfig) http.Handler {
	if cfg == nil {
		cfg = DefaultShield()
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		delay := tracker.getDelay(clientIP, cfg)

		if delay > 0 {
			fmt.Printf("[FIRE SHIELD] Intercepted IP: %s | Holding for %v...\n", clientIP, delay)
			time.Sleep(delay)

			accept := r.Header.Get("Accept")
			if strings.HasPrefix(accept, "text/html") || r.Header.Get("Sec-Fetch-Dest") == "document" {
				w.Header().Set("Content-Type", "text/html")
				delaySeconds := int(delay.Seconds())
				delayMs := int(delay.Milliseconds())
				fmt.Fprintf(w, verifyHTML, delaySeconds, delayMs)
				return
			}
		} else {
			fmt.Printf("[PASS] IP: %s | Direct pass-through\n", clientIP)
		}

		next.ServeHTTP(w, r)
	})
}

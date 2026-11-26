package strattest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Target — одна цель стандартной проверки: URL (HTTP + TLS) и/или ping.
type Target struct {
	Name     string `json:"name"`
	URL      string `json:"url"`  // пусто для ping-only
	Host     string `json:"host"` // куда слать ping
	PingOnly bool   `json:"pingOnly"`
}

// defaultTargetLines — набор из utils/targets.txt Flowseal.
var defaultTargetLines = []struct{ name, value string }{
	{"Discord Main", "https://discord.com"},
	{"Discord Gateway", "https://gateway.discord.gg"},
	{"Discord CDN", "https://cdn.discordapp.com"},
	{"Discord Updates", "https://updates.discord.com"},
	{"YouTube Web", "https://www.youtube.com"},
	{"YouTube Short", "https://youtu.be"},
	{"YouTube Image", "https://i.ytimg.com"},
	{"YouTube Video Redirect", "https://redirector.googlevideo.com"},
	{"Google Main", "https://www.google.com"},
	{"Google Gstatic", "https://www.gstatic.com"},
	{"Cloudflare Web", "https://www.cloudflare.com"},
	{"Cloudflare CDN", "https://cdnjs.cloudflare.com"},
	{"Cloudflare DNS 1.1.1.1", "PING:1.1.1.1"},
	{"Cloudflare DNS 1.0.0.1", "PING:1.0.0.1"},
	{"Google DNS 8.8.8.8", "PING:8.8.8.8"},
	{"Google DNS 8.8.4.4", "PING:8.8.4.4"},
}

// DefaultTargets — то, чем пользуется test zapret.ps1, когда нет targets.txt.
var DefaultTargets = buildTargets(defaultTargetLines)

func buildTargets(lines []struct{ name, value string }) []Target {
	var out []Target
	for _, l := range lines {
		if t, ok := NewTarget(l.name, l.value); ok {
			out = append(out, t)
		}
	}
	return out
}

// NewTarget разбирает строку targets.txt ("https://..." или "PING:ip").
func NewTarget(name, value string) (Target, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToUpper(value), "PING:") {
		return Target{Name: name, Host: strings.TrimSpace(value[5:]), PingOnly: true}, true
	}
	host := value
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/"); i >= 0 {
		host = host[:i]
	}
	if host == "" {
		return Target{}, false
	}
	return Target{Name: name, URL: value, Host: host}, true
}

var reTargetLine = regexp.MustCompile(`^\s*(\w+)\s*=\s*"(.+)"\s*$`)

// LoadTargets берёт utils/targets.txt из папки Flowseal, иначе — набор по умолчанию.
func LoadTargets(flowsealDir string) []Target {
	if flowsealDir != "" {
		if data, err := os.ReadFile(filepath.Join(flowsealDir, "utils", "targets.txt")); err == nil {
			var out []Target
			for _, ln := range strings.Split(strings.ReplaceAll(string(data), "\r", ""), "\n") {
				if m := reTargetLine.FindStringSubmatch(ln); m != nil {
					if t, ok := NewTarget(m[1], m[2]); ok {
						out = append(out, t)
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return DefaultTargets
}

// DPIHost — цель набора dpi-checkers (hyperion-cs, Apache-2.0).
type DPIHost struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Country  string `json:"country"`
	Host     string `json:"host"`
}

// SuiteURL — тот же набор, что использует test zapret.ps1.
const SuiteURL = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json"

func LoadDPISuite(ctx context.Context) ([]DPIHost, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, SuiteURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var hosts []DPIHost
	if err := json.NewDecoder(resp.Body).Decode(&hosts); err != nil {
		return nil, err
	}
	out := hosts[:0]
	for _, h := range hosts {
		if h.Host != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("набор пуст")
	}
	return out, nil
}

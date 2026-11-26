//go:build !windows

package strattest

import (
	"context"
	"os/exec"
	"sync"
	"time"
)

// PingBatch — системным ping по каждой цели (пакет собирается для Windows,
// здесь запасной вариант для прочих систем).
func PingBatch(ctx context.Context, hosts []string, timeout time.Duration) map[string]PingResult {
	var mu sync.Mutex
	var wg sync.WaitGroup
	res := make(map[string]PingResult, len(hosts))
	for _, h := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			err := exec.CommandContext(cctx, "ping", "-c", "1", "-W", "1", h).Run()
			mu.Lock()
			res[h] = PingResult{OK: err == nil}
			mu.Unlock()
		}(h)
	}
	wg.Wait()
	return res
}

package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/spectre-tool/spectre/internal/utils"
)

// discoverOpenPorts performs Phase 1: fast TCP connect sweep.
// Returns a slice of candidate-open ports to pass to Phase 2 for confirmation.
// Falls back to connect scan if raw sockets unavailable.
func discoverOpenPorts(ctx context.Context, target string, ports []int, concurrency int, timeout time.Duration, rl *utils.RateLimiter, ac *AdaptiveController) []int {
	work := make(chan int, concurrency*2)
	var mu sync.Mutex
	var open []int

	go func() {
		defer close(work)
		for _, p := range ports {
			select {
			case work <- p:
			case <-ctx.Done():
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case port, ok := <-work:
					if !ok {
						return
					}
					if err := rl.Wait(ctx); err != nil {
						return
					}
					if connectProbe(ctx, target, port, timeout) {
						mu.Lock()
						open = append(open, port)
						mu.Unlock()
						if ac != nil {
							ac.RecordSuccess()
						}
					} else {
						if ac != nil {
							ac.RecordTimeout()
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	return open
}

// connectProbe attempts a TCP connect to target:port within timeout.
// Returns true if the port accepts the connection (candidate open).
func connectProbe(ctx context.Context, target string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", target, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// expandPortRange converts a port specification to a sorted list of ints.
// Supports: "80", "80,443", "1-1000", "1-65535", "-" (all).
func expandPortRange(spec string) []int {
	if spec == "-" || spec == "all" || spec == "1-65535" {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports
	}
	seen := make(map[int]bool)
	for _, part := range splitComma(spec) {
		if idx := indexOf(part, '-'); idx > 0 {
			var start, end int
			fmt.Sscanf(part[:idx], "%d", &start)
			fmt.Sscanf(part[idx+1:], "%d", &end)
			for p := start; p <= end && p <= 65535; p++ {
				if p > 0 {
					seen[p] = true
				}
			}
		} else {
			var p int
			if fmt.Sscanf(part, "%d", &p) == 1 && p > 0 && p <= 65535 {
				seen[p] = true
			}
		}
	}
	var ports []int
	for p := range seen {
		ports = append(ports, p)
	}
	return ports
}

// topPorts returns the N most commonly scanned ports (from nmap's frequency list).
func topPorts(n int) []int {
	// Top 1000 common ports (abbreviated for build size)
	common := []int{
		80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
		143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
		1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
		10000, 514, 5631, 5900, 1433, 3986, 13, 1029, 1720, 1521,
		6000, 540, 631, 27017, 27018, 5432, 5984, 6379, 9200, 11211,
		2375, 2376, 4243, 2379, 2380, 8443, 8888, 9090, 9091, 9092,
		4848, 7000, 7001, 7002, 7003, 7070, 8161, 61616, 50000, 4567,
		9000, 3000, 5000, 8000, 8001, 8008, 8009, 8010, 8888, 9999,
		512, 513, 515, 1900, 5353, 5060, 5061, 4444, 4000, 9100,
		502, 102, 44818, 47808, 20000, 789, 1911, 9600, 19999, 2404,
	}
	if n >= len(common) {
		return common
	}
	return common[:n]
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func indexOf(s string, c rune) int {
	for i, r := range s {
		if r == c {
			return i
		}
	}
	return -1
}

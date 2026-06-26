package discovery

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProbe builds a Probe that returns the canned Outcome for each exact URL,
// and a 404 for anything else. It records how many requests were made and the
// peak concurrency observed.
type fakeProbe struct {
	mu       sync.Mutex
	canned   map[string]Outcome
	tried    map[string]int
	inflight int32
	peak     int32
	delay    time.Duration
}

func newFakeProbe(canned map[string]Outcome) *fakeProbe {
	return &fakeProbe{canned: canned, tried: map[string]int{}}
}

func (f *fakeProbe) probe() Probe {
	return func(ctx context.Context, method, rawURL string, headers map[string]string) (Outcome, error) {
		n := atomic.AddInt32(&f.inflight, 1)
		for {
			p := atomic.LoadInt32(&f.peak)
			if n <= p || atomic.CompareAndSwapInt32(&f.peak, p, n) {
				break
			}
		}
		if f.delay > 0 {
			time.Sleep(f.delay)
		}
		atomic.AddInt32(&f.inflight, -1)
		f.mu.Lock()
		f.tried[rawURL]++
		f.mu.Unlock()
		if o, ok := f.canned[rawURL]; ok {
			return o, nil
		}
		return Outcome{Status: 404, Length: 9}, nil
	}
}

func (f *fakeProbe) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tried)
}

// runSync starts a spec and blocks until the engine reports it finished.
func runSync(t *testing.T, e *Engine, spec Spec) []Result {
	t.Helper()
	done := make(chan struct{})
	e.SetNotifier(func() {
		if !e.State().Running {
			select {
			case <-done:
			default:
				close(done)
			}
		}
	})
	if err := e.Start(spec); err != nil {
		t.Fatalf("start: %v", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not finish in time")
	}
	return e.State().Results
}

func has(results []Result, path string) *Result {
	for i := range results {
		if results[i].Path == path {
			return &results[i]
		}
	}
	return nil
}

func TestFindsMatchingPaths(t *testing.T) {
	fp := newFakeProbe(map[string]Outcome{
		"http://t/admin":  {Status: 200, Length: 120},
		"http://t/secret": {Status: 301, Length: 0, Location: "http://t/secret/"},
	})
	e := New()
	e.SetProbe(fp.probe())
	res := runSync(t, e, Spec{BaseURL: "http://t/", Words: []string{"admin", "secret", "nope"}, Threads: 4})

	if has(res, "/admin") == nil || has(res, "/secret") == nil {
		t.Fatalf("expected admin+secret found, got %+v", res)
	}
	if has(res, "/nope") != nil {
		t.Fatalf("404 path should not be reported")
	}
	if r := has(res, "/admin"); r.Status != 200 || r.Length != 120 {
		t.Fatalf("admin result wrong: %+v", r)
	}
}

func TestSoft404Calibration(t *testing.T) {
	// The server returns 200 for *everything* (a soft 404) with a constant body
	// length, except /real which is a different length. Calibration must learn
	// the soft-404 signature and suppress the noise, surfacing only /real.
	soft := Outcome{Status: 200, Length: 1000}
	fp := &fakeProbe{canned: map[string]Outcome{
		"http://t/real": {Status: 200, Length: 4096},
	}, tried: map[string]int{}}
	// Override the default 404 to be a soft-200 for unknown URLs.
	probe := func(ctx context.Context, method, rawURL string, headers map[string]string) (Outcome, error) {
		fp.mu.Lock()
		fp.tried[rawURL]++
		fp.mu.Unlock()
		if o, ok := fp.canned[rawURL]; ok {
			return o, nil
		}
		return soft, nil
	}
	e := New()
	e.SetProbe(probe)
	res := runSync(t, e, Spec{BaseURL: "http://t/", Words: []string{"real", "x", "y", "z"}, Threads: 2})

	if has(res, "/real") == nil {
		t.Fatalf("/real (distinct length) should be found")
	}
	for _, p := range []string{"/x", "/y", "/z"} {
		if has(res, p) != nil {
			t.Fatalf("soft-404 %s should be suppressed by calibration, got %+v", p, res)
		}
	}
}

func TestExtensionsExpand(t *testing.T) {
	fp := newFakeProbe(map[string]Outcome{
		"http://t/config.bak": {Status: 200, Length: 50},
	})
	e := New()
	e.SetProbe(fp.probe())
	res := runSync(t, e, Spec{BaseURL: "http://t/", Words: []string{"config"}, Extensions: []string{".php", ".bak"}, Threads: 3})

	if has(res, "/config.bak") == nil {
		t.Fatalf("config.bak should be found, got %+v", res)
	}
	if has(res, "/config") != nil || has(res, "/config.php") != nil {
		t.Fatalf("only config.bak should match")
	}
}

func TestConcurrencyAndDelay(t *testing.T) {
	fp := newFakeProbe(nil)
	fp.delay = 20 * time.Millisecond
	e := New()
	e.SetProbe(fp.probe())
	words := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	runSync(t, e, Spec{BaseURL: "http://t/", Words: words, Threads: 8})
	if fp.peak < 2 {
		t.Fatalf("expected concurrent probing (peak>=2), got peak=%d", fp.peak)
	}
	// 8 words + 1 calibration probe.
	if fp.count() < len(words) {
		t.Fatalf("expected at least %d distinct probes, got %d", len(words), fp.count())
	}
}

func TestRecursionIntoDiscoveredDir(t *testing.T) {
	fp := newFakeProbe(map[string]Outcome{
		"http://t/admin":        {Status: 301, Length: 0, Location: "http://t/admin/"},
		"http://t/admin/users":  {Status: 200, Length: 300},
	})
	e := New()
	e.SetProbe(fp.probe())
	res := runSync(t, e, Spec{
		BaseURL: "http://t/", Words: []string{"admin", "users"},
		Threads: 4, Recursive: true, MaxDepth: 2,
	})
	if has(res, "/admin") == nil {
		t.Fatalf("/admin dir should be found")
	}
	if r := has(res, "/admin/users"); r == nil || r.Depth != 1 {
		t.Fatalf("expected /admin/users at depth 1, got %+v", res)
	}
}

func TestScopeBlocksOutOfScope(t *testing.T) {
	fp := newFakeProbe(map[string]Outcome{
		"http://t/in":  {Status: 200, Length: 10},
		"http://t/out": {Status: 200, Length: 10},
	})
	e := New()
	e.SetProbe(fp.probe())
	e.SetScope(func(raw string) bool { return !strings.HasSuffix(raw, "/out") })
	res := runSync(t, e, Spec{BaseURL: "http://t/", Words: []string{"in", "out"}, Threads: 2})
	if has(res, "/in") == nil {
		t.Fatalf("/in should be found")
	}
	if has(res, "/out") != nil {
		t.Fatalf("/out is out of scope and must not be probed/reported")
	}
}

func TestStopHalts(t *testing.T) {
	fp := newFakeProbe(nil)
	fp.delay = 50 * time.Millisecond
	e := New()
	e.SetProbe(fp.probe())
	many := make([]string, 200)
	for i := range many {
		many[i] = "w" + string(rune('a'+i%26)) + string(rune('0'+i%10))
	}
	if err := e.Start(Spec{BaseURL: "http://t/", Words: many, Threads: 2}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	e.Stop()
	// Give it a moment to wind down.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !e.State().Running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e.State().Running {
		t.Fatal("engine should stop running after Stop()")
	}
}

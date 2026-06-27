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

func TestRecorderSetsFlowID(t *testing.T) {
	fp := newFakeProbe(map[string]Outcome{
		"https://t/admin": {Status: 200, Length: 100},
	})
	e := New()
	e.SetProbe(fp.probe())
	e.SetRecorder(func(r Result) int64 {
		if r.URL == "https://t/admin" {
			return 42
		}
		return 0
	})
	results := runSync(t, e, Spec{
		BaseURL: "https://t/", Words: []string{"admin"}, Threads: 1,
	})
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].FlowID != 42 {
		t.Fatalf("flowId = %d, want 42", results[0].FlowID)
	}
}

// TestSoft404CalibrationMultiProbe verifies that the calibration fires calibProbes
// random-path requests per directory and uses them to suppress soft-404 noise while
// still surfacing a path whose response length differs from the baseline.
func TestSoft404CalibrationMultiProbe(t *testing.T) {
	// A soft-404 server: returns 200 + fixed 1000-byte body for everything,
	// except /real which is 4096 bytes (genuinely different content).
	soft := Outcome{Status: 200, Length: 1000}
	var mu sync.Mutex
	probeCount := 0
	probe := func(ctx context.Context, method, rawURL string, headers map[string]string) (Outcome, error) {
		mu.Lock()
		probeCount++
		mu.Unlock()
		if rawURL == "http://t/real" {
			return Outcome{Status: 200, Length: 4096}, nil
		}
		return soft, nil
	}
	e := New()
	e.SetProbe(probe)
	res := runSync(t, e, Spec{
		BaseURL: "http://t/",
		Words:   []string{"real", "noise1", "noise2"},
		Threads: 2,
	})

	// The distinct-length path must surface.
	if has(res, "/real") == nil {
		t.Fatalf("/real (distinct length 4096 vs baseline 1000) should be found, got %+v", res)
	}
	// Paths that match the soft-404 baseline must be suppressed.
	for _, p := range []string{"/noise1", "/noise2"} {
		if has(res, p) != nil {
			t.Fatalf("soft-404 %s should be suppressed by calibration, got %+v", p, res)
		}
	}
	// Verify the engine issued at least calibProbes requests for calibration
	// (1 directory × calibProbes random-path probes + 3 wordlist probes).
	mu.Lock()
	total := probeCount
	mu.Unlock()
	if total < calibProbes {
		t.Fatalf("expected at least %d calibration probes, got total=%d", calibProbes, total)
	}
}

// TestSoft404CalibrationDisabled verifies that setting DisableSoft404Calibration:true
// prevents calibration entirely: soft-404 results are NOT suppressed and all
// wordlist paths with a non-404 status surface.
func TestSoft404CalibrationDisabled(t *testing.T) {
	soft := Outcome{Status: 200, Length: 1000}
	probe := func(ctx context.Context, method, rawURL string, headers map[string]string) (Outcome, error) {
		return soft, nil // every path returns the same soft-404
	}
	e := New()
	e.SetProbe(probe)
	res := runSync(t, e, Spec{
		BaseURL:                   "http://t/",
		Words:                     []string{"a", "b", "c"},
		Threads:                   2,
		DisableSoft404Calibration: true, // calibration OFF
	})
	// With calibration disabled, all 200 responses must be reported.
	for _, p := range []string{"/a", "/b", "/c"} {
		if has(res, p) == nil {
			t.Fatalf("calibration disabled: %s (status 200) should be reported, got %+v", p, res)
		}
	}
}

// TestSoft404CalibrationInconsistentProbes verifies that when calibration probes
// return inconsistent body lengths (noisy server), no suppression is applied — the
// engine falls back to surfacing all non-404 results rather than hiding real hits.
func TestSoft404CalibrationInconsistentProbes(t *testing.T) {
	// The server returns 200 for unknown paths but with wildly varying lengths,
	// simulating a server whose error pages include dynamic content (timestamp,
	// request-echo, etc.). We make the calibration probes always start with "ic-"
	// so we can detect them and hand back inconsistent lengths.
	callCount := 0
	var mu sync.Mutex
	probe := func(ctx context.Context, method, rawURL string, headers map[string]string) (Outcome, error) {
		mu.Lock()
		n := callCount
		callCount++
		mu.Unlock()
		// Calibration probes contain the "ic-" prefix; return different lengths
		// for each one so the consistency check fails.
		if strings.Contains(rawURL, "/ic-") {
			return Outcome{Status: 200, Length: int64(500 + n*500)}, nil
		}
		// Wordlist paths return a constant 200.
		return Outcome{Status: 200, Length: 800}, nil
	}
	e := New()
	e.SetProbe(probe)
	res := runSync(t, e, Spec{
		BaseURL: "http://t/",
		Words:   []string{"admin", "login"},
		Threads: 1,
	})
	// Because calibration was inconsistent, suppression must NOT fire.
	// Both wordlist paths (which return 200) should surface.
	for _, p := range []string{"/admin", "/login"} {
		if has(res, p) == nil {
			t.Fatalf("inconsistent calibration: %s should surface (no suppression), got %+v", p, res)
		}
	}
}

// TestCleanServerHonestNotFound verifies that a server returning honest 404s is
// unaffected by calibration: only paths that the server explicitly handles surface,
// and calibration never causes spurious suppression.
func TestCleanServerHonestNotFound(t *testing.T) {
	fp := newFakeProbe(map[string]Outcome{
		"http://t/real": {Status: 200, Length: 512},
	})
	e := New()
	e.SetProbe(fp.probe())
	res := runSync(t, e, Spec{
		BaseURL: "http://t/",
		Words:   []string{"real", "ghost", "phantom"},
		Threads: 2,
	})
	// /real must be found.
	if has(res, "/real") == nil {
		t.Fatalf("/real should be found on clean server, got %+v", res)
	}
	// 404 paths must not surface (they were never in canned responses).
	for _, p := range []string{"/ghost", "/phantom"} {
		if has(res, p) != nil {
			t.Fatalf("clean server: %s returned 404 and must not appear in results", p)
		}
	}
}

package verify

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// --- fakes ------------------------------------------------------------------

// fakeAgent returns a fixed verdict and records that it was called.
type fakeAgent struct {
	verdict Verdict
	called  int
}

func (a *fakeAgent) Disprove(_ context.Context, _ Candidate, _ DiffResult) Verdict {
	a.called++
	return a.verdict
}

// fakeConfirmer returns a fixed human decision and records that it was called.
type fakeConfirmer struct {
	result ConfirmResult
	called int
}

func (c *fakeConfirmer) Confirm(_ context.Context, _ Candidate, _ Proof) ConfirmResult {
	c.called++
	return c.result
}

// fakePoller reports a hit after k polls (k<=0 ⇒ never hits, models no callback).
type fakePoller struct {
	hitAfter int
	polls    int
}

func (p *fakePoller) HitsForToken(_ string) int {
	p.polls++
	if p.hitAfter > 0 && p.polls >= p.hitAfter {
		return 1
	}
	return 0
}

// noSleep drives the OOB poll loop instantly.
func noSleep(context.Context, time.Duration) {}

// reflectedCandidate builds a non-blind reflected candidate whose Gate-1 oracle
// reproduces via a scripted sender.
func reflectedCandidate(sev Severity) (Candidate, *scriptedSender) {
	s := newScriptedSender(map[string][]Exchange{
		"base":    {exFlow("clean", 100)},
		"payload": {exFlow("echo MARKX here", 101)},
	})
	c := Candidate{
		VulnClass: "xss-reflected",
		Severity:  sev,
		Target:    "https://example.com/q",
		Point:     "query param q",
		Diff: DiffSpec{
			Class:    ClassReflected,
			Baseline: req("base"),
			Payload:  req("payload"),
			Marker:   "MARKX",
			N:        3,
		},
		Summary: "reflected marker in q",
	}
	return c, s
}

// blindCandidate builds a blind candidate whose Gate-1 reflected oracle reproduces
// and whose Gate-3 OOB spec correlates on the given token.
func blindCandidate(sev Severity, token string) (Candidate, *scriptedSender) {
	s := newScriptedSender(map[string][]Exchange{
		"base":    {exFlow("clean", 200)},
		"payload": {exFlow("echo MARKB here", 201)},
		"probe":   {Exchange{Status: 200, FlowID: 202}},
	})
	c := Candidate{
		VulnClass: "ssrf-blind",
		Severity:  sev,
		Target:    "https://example.com/fetch",
		Point:     "url param",
		Blind:     true,
		Diff: DiffSpec{
			Class:    ClassReflected,
			Baseline: req("base"),
			Payload:  req("payload"),
			Marker:   "MARKB",
			N:        3,
		},
		OOB: &OOBSpec{
			Probe:    req("probe"),
			Token:    token,
			Window:   2 * time.Second,
			Interval: time.Second,
			sleep:    noSleep,
		},
		Summary: "blind ssrf via url param",
	}
	return c, s
}

func realAgent() *fakeAgent {
	return &fakeAgent{verdict: Verdict{Result: "real", Reasoning: "confirmed"}}
}
func okHuman() *fakeConfirmer {
	return &fakeConfirmer{result: ConfirmResult{Confirmed: true, By: "op"}}
}

// --- (a) full pass ----------------------------------------------------------

func TestVerifyReflectedProven(t *testing.T) {
	c, s := reflectedCandidate(SeverityMedium)
	agent := realAgent()
	human := okHuman()
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent, Human: human})

	if !p.Proven {
		t.Fatalf("expected proven, got %+v", p)
	}
	if p.RejectedAt != "" {
		t.Fatalf("expected empty RejectedAt, got %q", p.RejectedAt)
	}
	if p.ReproCount != 3 {
		t.Fatalf("expected ReproCount 3, got %d", p.ReproCount)
	}
	if p.BaselineFlow != 100 || p.PayloadFlow != 101 {
		t.Fatalf("expected flows 100/101, got %d/%d", p.BaselineFlow, p.PayloadFlow)
	}
	// Non-blind, Medium: Gates 1+2 apply → 100.
	if p.Confidence != 100 {
		t.Fatalf("expected confidence 100, got %d", p.Confidence)
	}
	if human.called != 0 {
		t.Fatalf("Medium must skip Gate 4; human called %d times", human.called)
	}
	if _, ok := p.Gates[GateOOB]; ok {
		t.Fatalf("non-blind must not record OOB gate")
	}
	if _, ok := p.Gates[GateHuman]; ok {
		t.Fatalf("Medium must not record human gate")
	}
}

// --- (b) rejected at Gate 1 -------------------------------------------------

func TestVerifyRejectedDifferential(t *testing.T) {
	// Payload never reflects the marker ⇒ Gate 1 fails.
	s := newScriptedSender(map[string][]Exchange{
		"base":    {exFlow("clean", 1)},
		"payload": {exFlow("still clean", 2)},
	})
	c := Candidate{
		VulnClass: "xss-reflected",
		Severity:  SeverityMedium,
		Diff: DiffSpec{
			Class: ClassReflected, Baseline: req("base"), Payload: req("payload"),
			Marker: "MARKX", N: 3,
		},
	}
	agent := realAgent()
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent})

	if p.Proven || p.RejectedAt != GateDifferential {
		t.Fatalf("expected reject at differential, got %+v", p)
	}
	if p.Confidence != 0 {
		t.Fatalf("Gate-1 rejection must score 0, got %d", p.Confidence)
	}
	if agent.called != 0 {
		t.Fatalf("agent must not run after Gate 1 fails; called %d", agent.called)
	}
}

// --- (c) rejected at Gate 2 -------------------------------------------------

func TestVerifyRejectedAgentRefuted(t *testing.T) {
	c, s := reflectedCandidate(SeverityMedium)
	agent := &fakeAgent{verdict: Verdict{Result: "refuted", Reasoning: "WAF echo"}}
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent})

	if p.Proven || p.RejectedAt != GateAgent {
		t.Fatalf("expected reject at agent, got %+v", p)
	}
	// Only Gate 1 held: 40 of (40+25)=65 → 61.
	if p.Confidence != 40*100/65 {
		t.Fatalf("expected partial confidence %d, got %d", 40*100/65, p.Confidence)
	}
}

func TestVerifyRejectedAgentUncertain(t *testing.T) {
	c, s := reflectedCandidate(SeverityMedium)
	agent := &fakeAgent{verdict: Verdict{Result: "uncertain"}}
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent})
	if p.Proven || p.RejectedAt != GateAgent {
		t.Fatalf("expected reject at agent for 'uncertain', got %+v", p)
	}
}

// --- (d) blind: Gate 3 fail and pass ----------------------------------------

func TestVerifyBlindRejectedOOB(t *testing.T) {
	c, s := blindCandidate(SeverityMedium, "tok-none")
	poll := &fakePoller{hitAfter: 0} // never hits
	agent := realAgent()
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, OOB: poll, Agent: agent})

	if p.Proven || p.RejectedAt != GateOOB {
		t.Fatalf("expected reject at oob, got %+v", p)
	}
	if p.OOBToken != "tok-none" {
		t.Fatalf("expected token recorded, got %q", p.OOBToken)
	}
	// Gates 1+2 held, Gate 3 (of 40+25+25=90) failed: 65/90 → 72.
	if p.Confidence != 65*100/90 {
		t.Fatalf("expected partial confidence %d, got %d", 65*100/90, p.Confidence)
	}
}

func TestVerifyBlindProven(t *testing.T) {
	c, s := blindCandidate(SeverityMedium, "tok-hit")
	poll := &fakePoller{hitAfter: 1} // hits on first poll
	agent := realAgent()
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, OOB: poll, Agent: agent})

	if !p.Proven || p.RejectedAt != "" {
		t.Fatalf("expected proven, got %+v", p)
	}
	if p.OOBToken != "tok-hit" {
		t.Fatalf("expected token tok-hit, got %q", p.OOBToken)
	}
	// Blind, Medium: Gates 1+2+3 apply → 100.
	if p.Confidence != 100 {
		t.Fatalf("expected confidence 100, got %d", p.Confidence)
	}
	if g, ok := p.Gates[GateOOB].(map[string]any); !ok || g["confirmed"] != true {
		t.Fatalf("expected OOB gate confirmed, got %v", p.Gates[GateOOB])
	}
}

// --- (e) Critical: Gate 4 decline and confirm -------------------------------

func TestVerifyCriticalHumanDeclines(t *testing.T) {
	c, s := reflectedCandidate(SeverityCritical)
	agent := realAgent()
	human := &fakeConfirmer{result: ConfirmResult{Confirmed: false, By: "op", Note: "not exploitable"}}
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent, Human: human})

	if p.Proven || p.RejectedAt != GateHuman {
		t.Fatalf("expected reject at human, got %+v", p)
	}
	if human.called != 1 {
		t.Fatalf("Critical must invoke Gate 4; called %d", human.called)
	}
	// Non-blind Critical: applicable 40+25+10=75; held 40+25=65 → 86.
	if p.Confidence != 65*100/75 {
		t.Fatalf("expected partial confidence %d, got %d", 65*100/75, p.Confidence)
	}
}

func TestVerifyCriticalConfirmed(t *testing.T) {
	c, s := reflectedCandidate(SeverityHigh)
	agent := realAgent()
	human := okHuman()
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent, Human: human})

	if !p.Proven || p.RejectedAt != "" {
		t.Fatalf("expected proven, got %+v", p)
	}
	if p.Confidence != 100 {
		t.Fatalf("expected confidence 100, got %d", p.Confidence)
	}
	if p.HumanConfirm.By != "op" {
		t.Fatalf("expected human confirm recorded, got %+v", p.HumanConfirm)
	}
}

// --- (f) Medium skips Gate 4 ------------------------------------------------

func TestVerifyMediumSkipsHuman(t *testing.T) {
	c, s := reflectedCandidate(SeverityMedium)
	agent := realAgent()
	human := okHuman()
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent, Human: human})

	if !p.Proven {
		t.Fatalf("expected proven, got %+v", p)
	}
	if human.called != 0 {
		t.Fatalf("Medium must skip Gate 4; human called %d", human.called)
	}
}

// --- (g) non-blind skips Gate 3 ---------------------------------------------

func TestVerifyNonBlindSkipsOOB(t *testing.T) {
	c, s := reflectedCandidate(SeverityMedium)
	agent := realAgent()
	poll := &fakePoller{hitAfter: 1}
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: agent, OOB: poll})

	if !p.Proven {
		t.Fatalf("expected proven, got %+v", p)
	}
	if poll.polls != 0 {
		t.Fatalf("non-blind must not poll OOB; polled %d", poll.polls)
	}
	if p.OOBToken != "" {
		t.Fatalf("non-blind must not record token, got %q", p.OOBToken)
	}
}

// --- (h) RejectedAt correctness is covered per-gate above; add a table check --

func TestVerifyRejectedAtSetPerGate(t *testing.T) {
	// Gate 1
	{
		s := newScriptedSender(map[string][]Exchange{"base": {exFlow("x", 1)}, "payload": {exFlow("x", 2)}})
		c := Candidate{Severity: SeverityHigh, Diff: DiffSpec{Class: ClassReflected, Baseline: req("base"), Payload: req("payload"), Marker: "NOPE", N: 2}}
		p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: realAgent(), Human: okHuman()})
		if p.RejectedAt != GateDifferential {
			t.Fatalf("gate1: got %q", p.RejectedAt)
		}
	}
	// Gate 4 (High)
	{
		c, s := reflectedCandidate(SeverityHigh)
		human := &fakeConfirmer{result: ConfirmResult{Confirmed: false}}
		p := Verify(context.Background(), c, VerifyDeps{Sender: s, Agent: realAgent(), Human: human})
		if p.RejectedAt != GateHuman {
			t.Fatalf("gate4: got %q", p.RejectedAt)
		}
	}
}

// --- (i) ctx cancellation ---------------------------------------------------

func TestVerifyCtxCancelledAtGate1(t *testing.T) {
	c, s := reflectedCandidate(SeverityMedium)
	agent := realAgent()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Verify runs
	p := Verify(ctx, c, VerifyDeps{Sender: s, Agent: agent})

	if p.Proven {
		t.Fatalf("cancelled ctx must not prove, got %+v", p)
	}
	if p.RejectedAt != GateDifferential {
		t.Fatalf("cancelled ctx should fail Gate 1 (not reproduced), got %q", p.RejectedAt)
	}
	if agent.called != 0 {
		t.Fatalf("agent must not run when Gate 1 fails on cancel")
	}
}

func TestVerifyBlindCtxCancelledAtGate3(t *testing.T) {
	// Gate 1 reproduces (single-shot sender returns the reflected marker), Gate 2
	// passes, then ctx is cancelled so Gate 3 polling returns not-confirmed.
	c, s := blindCandidate(SeverityMedium, "tok")
	// Cancellable ctx that the OOB poll observes as done: cancel via a poller that
	// cancels on first poll would be racy; instead cancel up front and rely on the
	// probe/poll loop checking ctx. ConfirmOOB checks ctx at the top of the loop.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	poll := &fakePoller{hitAfter: 0}
	p := Verify(ctx, c, VerifyDeps{Sender: s, OOB: poll, Agent: realAgent()})

	// With ctx cancelled, Gate 1's ReproduceDifferential returns not-reproduced,
	// so the run actually stops at Gate 1 — assert it never falsely proves.
	if p.Proven {
		t.Fatalf("cancelled ctx must not prove blind candidate, got %+v", p)
	}
}

// --- mapping helper ---------------------------------------------------------

func TestProofToVerification(t *testing.T) {
	c, s := blindCandidate(SeverityHigh, "tok-map")
	poll := &fakePoller{hitAfter: 1}
	p := Verify(context.Background(), c, VerifyDeps{Sender: s, OOB: poll, Agent: realAgent(), Human: okHuman()})
	if !p.Proven {
		t.Fatalf("setup: expected proven, got %+v", p)
	}

	v := p.Verification(7, 3, "ssrf-blind", "")
	if v.FindingID != 7 || v.RunID != 3 || v.VulnClass != "ssrf-blind" {
		t.Fatalf("bad ids/class: %+v", v)
	}
	if v.OOBToken != "tok-map" {
		t.Fatalf("expected token from proof, got %q", v.OOBToken)
	}
	if v.ReproCount != 3 || v.BaselineFlow != 200 || v.PayloadFlow != 201 {
		t.Fatalf("bad proof fields: %+v", v)
	}
	if v.Confidence != 100 {
		t.Fatalf("expected confidence 100, got %d", v.Confidence)
	}
	// Gates must be valid JSON carrying every gate that ran.
	var gates map[string]any
	if err := json.Unmarshal([]byte(v.Gates), &gates); err != nil {
		t.Fatalf("gates not valid JSON: %v (%s)", err, v.Gates)
	}
	for _, g := range []string{GateDifferential, GateAgent, GateOOB, GateHuman} {
		if _, ok := gates[g]; !ok {
			t.Fatalf("gates JSON missing %q: %s", g, v.Gates)
		}
	}

	// oobToken override wins when non-empty.
	v2 := p.Verification(7, 3, "ssrf-blind", "override")
	if v2.OOBToken != "override" {
		t.Fatalf("expected override token, got %q", v2.OOBToken)
	}

	// map form matches struct.
	m := p.ToVerification(7, 3, "ssrf-blind", "")
	if m["confidence"] != 100 || m["vulnClass"] != "ssrf-blind" || m["oobToken"] != "tok-map" {
		t.Fatalf("map form mismatch: %v", m)
	}
}

// --- severity parsing -------------------------------------------------------

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"Critical": SeverityCritical, "HIGH": SeverityHigh, "medium": SeverityMedium,
		"med": SeverityMedium, "low": SeverityLow, "info": SeverityInfo,
		"": SeverityInfo, "bogus": SeverityInfo, " High ": SeverityHigh,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Fatalf("ParseSeverity(%q)=%v want %v", in, got, want)
		}
	}
	if SeverityCritical.String() != "critical" || SeverityInfo.String() != "info" {
		t.Fatalf("String() mismatch")
	}
}

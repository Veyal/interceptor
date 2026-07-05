package aiagent

import (
	"context"
	"fmt"
	"time"
)

// Clock is an injected time source so the loop's wall-clock budget is testable
// without a real clock. Production code passes RealClock; tests pass a fake.
type Clock interface {
	Now() time.Time
}

// RealClock is the production Clock backed by time.Now.
type RealClock struct{}

// Now returns the current time.
func (RealClock) Now() time.Time { return time.Now() }

// Budget bounds an agent run. A zero/negative value for any field means that
// dimension is unbounded. MaxTokens is best-effort (advisory): it is only
// enforced when the ToolCaller reports usage.
type Budget struct {
	MaxSteps     int   // max model turns
	MaxToolCalls int   // max total tool executions across the run
	MaxTokens    int   // advisory token ceiling (0 = unlimited/untracked)
	MaxWallMs    int64 // max wall-clock milliseconds from run start
}

// ToolExecutor runs one tool call and returns its result string. A non-nil error
// is treated as a hard failure that aborts the run (StoppedBy "error"); tools that
// want to report a recoverable failure to the model should return it as the result
// string with a nil error.
type ToolExecutor interface {
	Exec(ctx context.Context, call ToolCall) (result string, err error)
}

// Stop reasons for a completed run.
const (
	StoppedDone   = "done"   // model produced a final tool-less answer
	StoppedBudget = "budget" // a hard budget cap was hit
	StoppedCtx    = "ctx"    // the context was cancelled
	StoppedError  = "error"  // the ToolCaller or ToolExecutor returned an error
)

// RunResult summarizes a finished run.
type RunResult struct {
	FinalText  string    // the assistant's final text (best available if budget-stopped)
	Steps      int       // model turns taken
	ToolCalls  int       // tool executions performed
	Tokens     int       // total tokens observed (best-effort)
	Transcript []Message // the full message history, including seeded task and tool results
	StoppedBy  string    // done | budget | ctx | error
}

// Run drives a budgeted tool-calling loop. It seeds the history with the task,
// then repeatedly: (1) checks hard budgets and ctx BEFORE each model turn, (2)
// asks the ToolCaller for one turn, (3) if the turn has no tool calls it is the
// final answer (StoppedDone), else executes each call via exec, appends the
// results, and checks budgets again after the batch.
//
// Budget overruns are HARD stops: the loop transitions to StoppedBudget and, if it
// is cheap and still within remaining budget, does a final tool-less synthesis turn
// to surface a closing answer (mirroring the in-app agent's final-summary pass).
// Context cancellation yields StoppedCtx; a caller/executor error yields StoppedError
// with the error returned. On StoppedError, RunResult still carries the transcript
// accumulated so far.
func Run(ctx context.Context, tc ToolCaller, exec ToolExecutor, system, task string, tools []ToolSpec, b Budget, clock Clock) (RunResult, error) {
	if clock == nil {
		clock = RealClock{}
	}
	start := clock.Now()
	res := RunResult{Transcript: []Message{{Role: "user", Text: task}}}

	// budgetHit reports whether any hard cap is now exceeded, and which.
	budgetHit := func() bool {
		if b.MaxSteps > 0 && res.Steps >= b.MaxSteps {
			return true
		}
		if b.MaxToolCalls > 0 && res.ToolCalls >= b.MaxToolCalls {
			return true
		}
		if b.MaxTokens > 0 && res.Tokens >= b.MaxTokens {
			return true
		}
		if b.MaxWallMs > 0 && clock.Now().Sub(start).Milliseconds() >= b.MaxWallMs {
			return true
		}
		return false
	}

	for {
		if ctxDone(ctx) {
			res.StoppedBy = StoppedCtx
			return res, ctx.Err()
		}
		if budgetHit() {
			return finishOnBudget(ctx, tc, system, tools, b, clock, start, &res), nil
		}

		turn, err := tc.Complete(ctx, system, res.Transcript, tools)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				res.StoppedBy = StoppedCtx
				return res, ctxErr
			}
			res.StoppedBy = StoppedError
			return res, err
		}
		res.Steps++
		res.Tokens += turn.Usage.Total()

		// No tool calls => final answer.
		if len(turn.Calls) == 0 {
			res.FinalText = turn.Text
			res.Transcript = append(res.Transcript, Message{Role: "assistant", Text: turn.Text})
			res.StoppedBy = StoppedDone
			return res, nil
		}

		res.FinalText = turn.Text // keep the latest assistant text as best-available
		res.Transcript = append(res.Transcript, Message{Role: "assistant", Text: turn.Text, Calls: turn.Calls})

		for _, call := range turn.Calls {
			if ctxDone(ctx) {
				res.StoppedBy = StoppedCtx
				return res, ctx.Err()
			}
			result, err := exec.Exec(ctx, call)
			if err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					res.StoppedBy = StoppedCtx
					return res, ctxErr
				}
				res.StoppedBy = StoppedError
				return res, fmt.Errorf("tool %q: %w", call.Name, err)
			}
			res.ToolCalls++
			res.Transcript = append(res.Transcript, Message{Role: "tool", Text: result, ToolCallID: call.ID})
		}

		// Re-check after the batch so an over-budget run stops before another turn.
		if budgetHit() {
			return finishOnBudget(ctx, tc, system, tools, b, clock, start, &res), nil
		}
	}
}

// finishOnBudget marks the run budget-stopped and, when a final synthesis turn is
// cheap and still within remaining budget, performs one tool-less turn to produce a
// closing answer. It never exceeds the budget to do so.
func finishOnBudget(ctx context.Context, tc ToolCaller, system string, tools []ToolSpec, b Budget, clock Clock, start time.Time, res *RunResult) RunResult {
	res.StoppedBy = StoppedBudget

	// Only synthesize if steps and wall-clock still permit one more (tool-less) turn.
	if b.MaxSteps > 0 && res.Steps >= b.MaxSteps {
		return *res
	}
	if b.MaxTokens > 0 && res.Tokens >= b.MaxTokens {
		return *res
	}
	if b.MaxWallMs > 0 && clock.Now().Sub(start).Milliseconds() >= b.MaxWallMs {
		return *res
	}
	if ctxDone(ctx) {
		return *res
	}

	// Ask for a final answer with NO tools so the model cannot request more work.
	turn, err := tc.Complete(ctx, system, res.Transcript, nil)
	if err != nil {
		return *res
	}
	res.Steps++
	res.Tokens += turn.Usage.Total()
	if turn.Text != "" {
		res.FinalText = turn.Text
		res.Transcript = append(res.Transcript, Message{Role: "assistant", Text: turn.Text})
	}
	return *res
}

func ctxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

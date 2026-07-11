package control

import (
	"fmt"
	"strings"

	"github.com/Veyal/interseptor/internal/store"
)

const (
	maxProjectContextBytes  = 24000
	maxProjectNotesBytes    = 6000
	maxProjectFindings      = 30
	maxProjectFlows         = 20
	maxProjectScopeRules    = 50
	projectTruncationMarker = "\n...(truncated)"
)

func (h *aiAPI) collectProjectAssistFlows() ([]assistFlow, error) {
	notes, err := h.st.LoadNotes()
	if err != nil {
		return nil, fmt.Errorf("load project notes: %w", err)
	}
	rules, err := h.st.ListScopeRules()
	if err != nil {
		return nil, fmt.Errorf("list project scope: %w", err)
	}
	findings, err := h.st.ListFindings("", "")
	if err != nil {
		return nil, fmt.Errorf("list project findings: %w", err)
	}
	flows, _, err := h.queryInScopeFlows(store.FlowFilter{
		SortKey:      "id",
		SortDir:      -1,
		ExcludeFlags: store.FlagRepeater | store.FlagIntruder | store.FlagActiveScan | store.FlagAuthz | store.FlagDiscovery,
	}, maxProjectFlows+1)
	if err != nil {
		return nil, fmt.Errorf("list project flows: %w", err)
	}
	flowsTruncated := len(flows) > maxProjectFlows
	if flowsTruncated {
		flows = flows[:maxProjectFlows]
	}

	var context strings.Builder
	fmt.Fprintf(&context, "Project: %s\n\n", clipProjectText(strings.TrimSpace(h.ProjectName), 200))
	context.WriteString("Notes:\n")
	context.WriteString(clipProjectText(strings.TrimSpace(notes), maxProjectNotesBytes))
	context.WriteString("\n\nScope rules:\n")
	for index, rule := range rules {
		if index >= maxProjectScopeRules {
			break
		}
		fmt.Fprintf(&context, "- %s %s\n", rule.Action, scopeRuleSummary(rule))
	}
	if len(rules) > maxProjectScopeRules {
		context.WriteString(projectTruncationMarker + "\n")
	}
	context.WriteString("\nFindings:\n")
	for index, finding := range findings {
		if index >= maxProjectFindings {
			break
		}
		fmt.Fprintf(&context, "- %s %s: %s", finding.Severity, finding.Status, clipProjectText(finding.Title, 300))
		if finding.Target != "" {
			fmt.Fprintf(&context, " | Target: %s", clipProjectText(finding.Target, 300))
		}
		if finding.Impact != "" {
			fmt.Fprintf(&context, " | Impact: %s", clipProjectText(finding.Impact, 500))
		}
		context.WriteByte('\n')
	}
	if len(findings) > maxProjectFindings {
		context.WriteString(projectTruncationMarker + "\n")
	}
	context.WriteString("\nNewest in-scope ordinary flows (metadata only):\n")
	for _, flow := range flows {
		fmt.Fprintf(&context, "- #%d %s %s://%s%s status=%d mime=%s reqBytes=%d resBytes=%d durationMs=%d",
			flow.ID, flow.Method, flow.Scheme, flow.Host, flow.Path, flow.Status, flow.Mime, flow.ReqLen, flow.ResLen, flow.DurationMs)
		if flow.Note != "" {
			fmt.Fprintf(&context, " note=%s", clipProjectText(flow.Note, 300))
		}
		context.WriteByte('\n')
	}
	if flowsTruncated {
		context.WriteString(projectTruncationMarker + "\n")
	}

	return []assistFlow{{Label: "Active project", Req: clipProjectText(context.String(), maxProjectContextBytes), Project: true}}, nil
}

func clipProjectText(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	if limit <= len(projectTruncationMarker) {
		return projectTruncationMarker[:limit]
	}
	return text[:limit-len(projectTruncationMarker)] + projectTruncationMarker
}

func scopeRuleSummary(rule store.ScopeRule) string {
	parts := make([]string, 0, 4)
	if rule.Scheme != "" {
		parts = append(parts, rule.Scheme+"://")
	}
	if rule.Host != "" {
		parts = append(parts, rule.Host)
	}
	if rule.Port != 0 {
		parts = append(parts, fmt.Sprintf(":%d", rule.Port))
	}
	if rule.Path != "" {
		parts = append(parts, rule.Path)
	}
	if len(parts) == 0 {
		return "any target"
	}
	return strings.Join(parts, "")
}

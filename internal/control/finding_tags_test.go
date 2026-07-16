package control

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestFindingTagsAPIAndReport(t *testing.T) {
	h, _, _ := newHub(t)
	ts := httptest.NewServer(h.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/findings", "application/json",
		strings.NewReader(`{"title":"API IDOR","severity":"High","tags":["API","oauth"]}`))
	if err != nil {
		t.Fatal(err)
	}
	var created map[string]any
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	id, _ := created["id"].(float64)
	if id == 0 {
		t.Fatalf("create: %+v", created)
	}
	tags, _ := created["tags"].([]any)
	if len(tags) != 2 {
		t.Fatalf("create tags = %#v", created["tags"])
	}

	r, _ := http.Get(ts.URL + "/api/findings?tag=api")
	var lst struct {
		Findings []map[string]any `json:"findings"`
	}
	json.NewDecoder(r.Body).Decode(&lst)
	r.Body.Close()
	if len(lst.Findings) != 1 {
		t.Fatalf("list tag=api: got %d", len(lst.Findings))
	}

	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/findings/"+strconv.FormatInt(int64(id), 10),
		strings.NewReader(`{"tags":["cms","website"]}`))
	req.Header.Set("Content-Type", "application/json")
	pr, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var upd map[string]any
	json.NewDecoder(pr.Body).Decode(&upd)
	pr.Body.Close()
	ut, _ := upd["tags"].([]any)
	if len(ut) != 2 {
		t.Fatalf("patch tags = %#v", upd["tags"])
	}

	tr, _ := http.Get(ts.URL + "/api/findings/tags")
	var tagList struct {
		Tags []struct {
			Tag   string `json:"tag"`
			Count int    `json:"count"`
		} `json:"tags"`
	}
	json.NewDecoder(tr.Body).Decode(&tagList)
	tr.Body.Close()
	if len(tagList.Tags) < 2 {
		t.Fatalf("finding tags list: %+v", tagList.Tags)
	}

	rr, _ := http.Get(ts.URL + "/api/findings/report?groupBy=tag&format=md&includeBodies=0")
	body, _ := io.ReadAll(rr.Body)
	rr.Body.Close()
	if !strings.Contains(string(body), "## Tag: cms") && !strings.Contains(string(body), "## Tag: website") {
		t.Fatalf("grouped report missing tag sections:\n%s", body)
	}
	if !strings.Contains(string(body), "**Tags:**") {
		t.Fatalf("report missing Tags field:\n%s", body)
	}

	jr, _ := http.Get(ts.URL + "/api/findings/report?format=json&includeBodies=0")
	var jrep struct {
		Findings []map[string]any `json:"findings"`
	}
	json.NewDecoder(jr.Body).Decode(&jrep)
	jr.Body.Close()
	if len(jrep.Findings) != 1 {
		t.Fatalf("json report: %+v", jrep)
	}
	jt, _ := jrep.Findings[0]["tags"].([]any)
	if len(jt) != 2 {
		t.Fatalf("json report tags = %#v", jrep.Findings[0]["tags"])
	}
}

package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bgpsim/internal/server"
)

// newTestServer builds a server backed by a smaller generated network so the
// suite stays fast while still exercising the real handlers.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := server.NewForTest(4, 600)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func getJSON(t *testing.T, url string, out any) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("GET %s: %d", url, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
}

func postJSON(t *testing.T, url, body string, out any) int {
	t.Helper()
	res, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func TestStateAndTopology(t *testing.T) {
	ts := newTestServer(t)
	var st struct {
		Routers  int `json:"routers"`
		Prefixes int `json:"prefixes"`
		Sessions int `json:"sessions"`
		RPKI     struct {
			Total int `json:"total"`
		} `json:"rpki"`
	}
	getJSON(t, ts.URL+"/api/state", &st)
	if st.Routers < 10 || st.Prefixes < 100 || st.Sessions < 10 {
		t.Fatalf("implausible network: %+v", st)
	}
	if st.RPKI.Total == 0 {
		t.Fatal("RPKI stats are empty")
	}
	var topo struct {
		Routers []map[string]any `json:"routers"`
		Links   []map[string]any `json:"links"`
	}
	getJSON(t, ts.URL+"/api/topology", &topo)
	if len(topo.Routers) != st.Routers {
		t.Errorf("topology has %d routers, state says %d", len(topo.Routers), st.Routers)
	}
	if len(topo.Links) == 0 {
		t.Error("topology has no links")
	}
}

func TestRIBAndDecision(t *testing.T) {
	ts := newTestServer(t)
	var rib struct {
		Entries []struct {
			Prefix string `json:"prefix"`
			Best   struct {
				ASPath string `json:"asPath"`
			} `json:"best"`
		} `json:"entries"`
		Total int `json:"total"`
	}
	getJSON(t, ts.URL+"/api/rib?router=core-1&limit=5", &rib)
	if len(rib.Entries) == 0 {
		t.Fatal("core-1 RIB is empty")
	}
	if rib.Total < len(rib.Entries) {
		t.Fatal("total smaller than the returned page")
	}
	prefix := rib.Entries[0].Prefix
	var dec struct {
		Decision *struct {
			Candidates []struct {
				Reason string `json:"reason"`
			} `json:"candidates"`
			Steps []struct {
				Name string `json:"name"`
			} `json:"steps"`
		} `json:"decision"`
	}
	getJSON(t, ts.URL+"/api/decision?router=core-1&prefix="+prefix, &dec)
	if dec.Decision == nil {
		t.Fatal("no decision returned for an installed prefix")
	}
	if len(dec.Decision.Steps) == 0 {
		t.Error("decision trace has no steps")
	}
	for _, c := range dec.Decision.Candidates {
		if c.Reason == "" {
			t.Error("candidate without a reason")
		}
	}
}

func TestFaultAndReplay(t *testing.T) {
	ts := newTestServer(t)
	var topo struct {
		Routers []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			Role string `json:"role"`
		} `json:"routers"`
	}
	getJSON(t, ts.URL+"/api/topology", &topo)
	var borderID int = -1
	for _, r := range topo.Routers {
		if r.Role == "border" {
			borderID = r.ID
			break
		}
	}
	if borderID < 0 {
		t.Fatal("no border router")
	}
	body := `{"routerDown":[` + itoa(borderID) + `],"linkDown":[]}`
	var resp struct {
		Rounds  int `json:"rounds"`
		Updates int `json:"updates"`
	}
	if code := postJSON(t, ts.URL+"/api/faults", body, &resp); code != 200 {
		t.Fatalf("fault POST returned %d", code)
	}
	var rep struct {
		Rounds []struct {
			Round   int `json:"round"`
			Changes []struct {
				Router string `json:"router"`
			} `json:"changes"`
			Total int `json:"total"`
		} `json:"rounds"`
	}
	getJSON(t, ts.URL+"/api/replay", &rep)
	if len(rep.Rounds) == 0 {
		t.Fatal("replay has no rounds after a fault")
	}
	// Round numbers must be monotonic and start at 1.
	prev := 0
	for _, r := range rep.Rounds {
		if r.Round <= prev {
			t.Errorf("rounds out of order: %d after %d", r.Round, prev)
		}
		prev = r.Round
	}
}

func TestPolicyApplyAndValidation(t *testing.T) {
	ts := newTestServer(t)
	// Applying a syntactically valid policy set must succeed and reconverge.
	pols := `{"policies":[
		{"name":"deny-bogons","direction":"import",
		 "match":{"prefixList":[{"prefix":"10.0.0.0/8","ge":8,"le":32,"action":"permit"}]},
		 "actions":{"action":"deny"}}]}`
	var ok struct {
		OK     bool `json:"ok"`
		Rounds int  `json:"rounds"`
	}
	if code := postJSON(t, ts.URL+"/api/policies/apply", pols, &ok); code != 200 {
		t.Fatalf("apply returned %d", code)
	}
	if !ok.OK {
		t.Fatal("apply did not report success")
	}
	// A bad AS_PATH regex must be rejected with 400, not accepted silently.
	bad := `{"policies":[{"name":"bad","match":{"asPathRegex":"_["},"actions":{}}]}`
	var errResp map[string]string
	if code := postJSON(t, ts.URL+"/api/policies/apply", bad, &errResp); code != 400 {
		t.Fatalf("invalid regex returned %d, want 400", code)
	}
	if errResp["error"] == "" {
		t.Error("invalid regex returned no error message")
	}
}

func TestTrafficEndpoint(t *testing.T) {
	ts := newTestServer(t)
	var rep struct {
		Upstreams []struct {
			Link        string  `json:"link"`
			Utilisation float64 `json:"utilisation"`
		} `json:"upstreams"`
		Links []struct {
			Link string `json:"link"`
		} `json:"links"`
		TotalGbps float64 `json:"totalGbps"`
	}
	getJSON(t, ts.URL+"/api/traffic?flows=64", &rep)
	if len(rep.Upstreams) == 0 {
		t.Fatal("no upstream links")
	}
	if len(rep.Links) == 0 {
		t.Fatal("no links in the report")
	}
	if rep.TotalGbps <= 0 {
		t.Fatal("total traffic is zero")
	}
}

func TestDampeningRoundTrip(t *testing.T) {
	ts := newTestServer(t)
	var cur struct {
		Config map[string]any `json:"config"`
	}
	getJSON(t, ts.URL+"/api/dampening", &cur)
	body := `{"enabled":true,"penaltyPerFlap":1000,"suppressThreshold":2000,
		"reuseThreshold":750,"halfLifeSeconds":900,"maxPenalty":12000}`
	var resp struct {
		OK bool `json:"ok"`
	}
	if code := postJSON(t, ts.URL+"/api/dampening", body, &resp); code != 200 || !resp.OK {
		t.Fatalf("dampening update returned %d ok=%v", code, resp.OK)
	}
	getJSON(t, ts.URL+"/api/dampening", &cur)
	if cur.Config["enabled"] != true {
		t.Errorf("dampening config did not persist: %+v", cur.Config)
	}
}

// TestStaticFiles makes sure the embedded UI is actually served.
func TestStaticFiles(t *testing.T) {
	ts := newTestServer(t)
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("index returned %d", res.StatusCode)
	}
	buf := make([]byte, 2048)
	n, _ := res.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "BGP") {
		t.Error("index page does not look like the UI")
	}
	for _, path := range []string{"/app.js", "/app.css"} {
		r, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Errorf("%s returned %d", path, r.StatusCode)
		}
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

var _ = time.Second

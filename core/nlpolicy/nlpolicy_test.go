// nlpolicy tests: prompt building, response extraction, and the deterministic
// gate between a drafted policy and the compiled authority.
package nlpolicy_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/nlpolicy"
	"offense.dev/raid/core/policy"
)

// A scripted transport records what was invoked and replays a canned response.
type scripted struct {
	status   int
	body     []byte
	err      error
	lastURL  string
	lastKey  string
	lastBody []byte
}

func (s *scripted) PostJSON(url, apiKey string, body []byte, deadlineNs int64) (int, []byte, error) {
	s.lastURL = url
	s.lastKey = apiKey
	s.lastBody = body
	if s.err != nil {
		return 0, nil, s.err
	}
	return s.status, s.body, nil
}

func okResponse(yaml string) []byte {
	// chat/completions response with the assistant content carrying YAML.
	var sb strings.Builder
	sb.WriteString(`{"choices":[{"message":{"role":"assistant","content":`)
	sb.WriteString(canonical.Escape(yaml))
	sb.WriteString(`}}]}`)
	return []byte(sb.String())
}

func TestPromptCarriesStatement(t *testing.T) {
	p := nlpolicy.PromptFor(`allow github issue reads, deny repository deletion`)
	if !strings.Contains(p, `github issue reads`) {
		t.Errorf("prompt missing statement")
	}
	if !strings.Contains(p, `PolicyBundle`) {
		t.Errorf("prompt missing instruction")
	}
}

func TestChatBodyIsValidJSON(t *testing.T) {
	body := nlpolicy.ChatBody("", `allow reads`)
	v, err := canonical.Decode(body, canonical.DecodeOptions{})
	if err != nil {
		t.Errorf("chat body is not valid json: %v", err.Error())
	}
	if v.Kind() != canonical.VObject {
		t.Errorf("chat body not an object")
	}
	m, ok := v.AsMap()["messages"]
	if !ok || m.Kind() != canonical.VList || len(m.AsList()) != 2 {
		t.Errorf("expected two messages")
	}
	sys, _ := m.AsList()[0].AsMap()["content"]
	usr, _ := m.AsList()[1].AsMap()["content"]
	if !strings.Contains(sys.AsString(), `PolicyBundle`) {
		t.Errorf("system message missing constraints")
	}
	if !strings.Contains(usr.AsString(), `allow reads`) {
		t.Errorf("user message missing statement")
	}
}

func TestExtractPolicyYaml(t *testing.T) {
	yaml := `apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: demo, revision: 1}
defaults: {effect: deny}
rules:
  - id: reads
    match: {operations: [github.issues.get]}
    effect: allow
`
	out, err := nlpolicy.ExtractPolicyYaml(okResponse(yaml))
	if err != nil {
		t.Errorf("extract: %v", err.Error())
	}
	if !strings.Contains(out, `kind: PolicyBundle`) {
		t.Errorf("yaml missing body: %v", out)
	}
}

func TestStripFence(t *testing.T) {
	fenced := "```yaml\nkind: PolicyBundle\n```"
	out, err := nlpolicy.ExtractPolicyYaml(okResponse(fenced))
	if err != nil {
		t.Errorf("extract fenced: %v", err.Error())
	}
	if out != "kind: PolicyBundle" {
		t.Errorf("fence not stripped: %q", out)
	}
}

func TestTranslateDraftsPolicy(t *testing.T) {
	draft := `apiVersion: offense.dev/raid/v1alpha1
kind: PolicyBundle
metadata: {name: g, revision: 1}
defaults: {effect: deny}
rules:
  - id: reads
    match: {operations: [github.issues.get]}
    when: "true"
    effect: allow
`
	fake := &scripted{status: 200, body: okResponse(draft)}
	nlpolicy.SetTransport(fake)
	out, terr := nlpolicy.Translate(fake, nlpolicy.TranslateOptions{ApiKey: "sk-test", Model: "m"}, `only allow issue reads`)
	if terr != nil {
		t.Errorf("translate: %v", terr.Error())
	}
	if !strings.Contains(out, `kind: PolicyBundle`) {
		t.Errorf("draft missing policy")
	}
	// the draft still has to survive the deterministic gate before it is trusted
	sch, lerr := policy.LoadBundle([]byte(out), "t")
	if lerr != nil {
		t.Errorf("drafted policy did not validate: %v", lerr.Error())
	}
	if _, cerr := policy.CompileBundle(sch, policy.CompileOptions{}); cerr != nil {
		t.Errorf("drafted policy did not compile: %v", cerr.Error())
	}
}

func TestTranslateNeedsKey(t *testing.T) {
	_, terr := nlpolicy.Translate(nil, nlpolicy.TranslateOptions{}, `allow everything`)
	if terr == nil {
		t.Errorf("expected missing-key failure")
	}
	if !strings.Contains(terr.Error(), "key") {
		t.Errorf("unhelpful missing-key message: %v", terr.Error())
	}
}

func TestTranslateEmptyStatement(t *testing.T) {
	_, terr := nlpolicy.Translate(nil, nlpolicy.TranslateOptions{ApiKey: "k"}, `   `)
	if terr == nil {
		t.Errorf("expected empty-statement failure")
	}
}

func TestTranslateNon2xx(t *testing.T) {
	fake := &scripted{status: 401, body: []byte(`{"error":"unauthorized"}`)}
	nlpolicy.SetTransport(fake)
	_, terr := nlpolicy.Translate(fake, nlpolicy.TranslateOptions{ApiKey: "bad"}, `reads`)
	if terr == nil {
		t.Errorf("expected http status failure")
	}
	if !strings.Contains(terr.Error(), "401") {
		t.Errorf("status not surfaced: %v", terr.Error())
	}
}

func TestTranslateMalformedResponse(t *testing.T) {
	fake := &scripted{status: 200, body: []byte(`{"unexpected":true}`)}
	nlpolicy.SetTransport(fake)
	_, terr := nlpolicy.Translate(fake, nlpolicy.TranslateOptions{ApiKey: "k"}, `reads`)
	if terr == nil {
		t.Errorf("expected malformed-response failure")
	}
}

func TestDefaultTransportFailsClosed(t *testing.T) {
	// With no transport injected, the default client performs a real HTTPS
	// request. When that request fails, translation fails closed rather than
	// returning a draft or surfacing the key anywhere.
	_, terr := nlpolicy.Translate(nil, nlpolicy.TranslateOptions{
		ApiKey:     "sk-secret-leak-canary",
		Endpoint:   "https://127.0.0.1:1/", // closed port: immediate refusal
		DeadlineNs: 2_000_000_000,
	}, `reads`)
	if terr == nil {
		t.Fatalf("expected fail-closed error when the endpoint is unreachable")
	}
	if strings.Contains(terr.Error(), "sk-secret-leak-canary") {
		t.Errorf("transport error must not leak the api key: %v", terr.Error())
	}
}

// The default client is a real network transport, not a fail-always stub.
func TestDefaultTransportIsReal(t *testing.T) {
	// An invalid URL must fail at request construction, proving the default
	// client talks to net/http rather than short-circuiting.
	_, terr := nlpolicy.Translate(nil, nlpolicy.TranslateOptions{
		ApiKey:   "k",
		Endpoint: "::not-a-url::",
	}, `reads`)
	if terr == nil {
		t.Fatalf("expected an error for an invalid endpoint")
	}
	if !strings.Contains(terr.Error(), "request") {
		t.Errorf("expected a request-construction error, got: %v", terr.Error())
	}
}

func TestDefaultTransportSendsRealRequest(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"kind: PolicyBundle"}}]}`)
	}))
	defer srv.Close()

	out, terr := nlpolicy.Translate(nil, nlpolicy.TranslateOptions{
		ApiKey:   "sk-test",
		Endpoint: srv.URL,
	}, `only allow issue reads`)
	if terr != nil {
		t.Fatalf("translate: %v", terr.Error())
	}
	if out != "kind: PolicyBundle" {
		t.Errorf("unexpected policy: %q", out)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("authorization header: %q", gotAuth)
	}
	if !strings.Contains(gotBody, "messages") || !strings.Contains(gotBody, "issue reads") {
		t.Errorf("chat body not sent: %q", gotBody)
	}
}

// --- TUI renderer ---

func TestTUIViewRendersFields(t *testing.T) {
	m := nlpolicy.NewModel("sk-or-test", "openrouter/auto", "allow issue reads")
	out := m.ViewText()
	if !strings.Contains(out, "OpenRouter key") {
		t.Errorf("missing key label")
	}
	if !strings.Contains(out, "Permissions") {
		t.Errorf("missing permissions label")
	}
	if !strings.Contains(out, "••••••••") {
		t.Errorf("key not masked")
	}
	if !strings.Contains(out, "allow issue reads") {
		t.Errorf("missing statement value")
	}
}

func TestTUIViewRendersDraft(t *testing.T) {
	m := nlpolicy.NewDraftModel("apiVersion: offense.dev/raid/v1alpha1\nkind: PolicyBundle\nrules: []")
	out := m.ViewText()
	if !strings.Contains(out, "Review") {
		t.Errorf("missing review panel")
	}
	if !strings.Contains(out, "kind: PolicyBundle") {
		t.Errorf("draft body not rendered")
	}
}

func TestTUIMasksUnsetKey(t *testing.T) {
	m := nlpolicy.NewModel("", "openrouter/auto", "reads")
	out := m.ViewText()
	if strings.Contains(out, "sk-or") {
		t.Errorf("key leaked when unset")
	}
}


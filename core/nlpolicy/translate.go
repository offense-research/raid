// OpenRouter-backed natural-language policy authoring.
//
// An operator describes their permissions in plain language, and an LLM
// (served over OpenRouter's OpenAI-compatible chat/completions API) drafts a
// YAML PolicyBundle. The draft is NEVER trusted as authority: the CLI strictly
// loads and compiles it with the deterministic policy pipeline before it is
// emitted or activated. The model is an authoring aid only; it can never
// loosen, override, or grant beyond deterministic policy (docs/threat-model.md).
package nlpolicy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/offense-research/raid/core/canonical"
)

// DefaultEndpoint is OpenRouter's OpenAI-compatible chat completions endpoint.
const DefaultEndpoint = "https://openrouter.ai/api/v1/chat/completions"

// DefaultModel is selected when the caller does not pin one.
const DefaultModel = "openrouter/auto"

// KeyEnv is the environment variable that carries the user's OpenRouter key.
const KeyEnv = "OPENROUTER_API_KEY"

// DefaultDeadlineNs bounds a single translation request (default 60s).
const DefaultDeadlineNs = 60_000_000_000

// TranslateOptions configures one natural-language translation.
type TranslateOptions struct {
	ApiKey     string
	Model      string
	Endpoint   string
	DeadlineNs int64
}

// systemPrompt constrains the model to emit exactly one valid PolicyBundle.
const systemPrompt = `You translate permissions written in plain language into a single YAML
document that describes an offense.dev/raid PolicyBundle. Return ONLY the YAML:
no markdown code fence, no surrounding text, no explanation.

The document MUST exactly match this shape:
  apiVersion: "offense.dev/raid/v1alpha1"
  kind: PolicyBundle
  metadata: { name: <slug>, revision: <positive integer> }
  defaults: { effect: deny }
  rules:
    - id: <unique slug>
      description: <short sentence>
      match:
        providers: [<provider>]
        operations: [<operation>]
        effects: [<read|write|...>]
        environments: [<environment>]
      when: <optional CEL boolean expression>
      effect: allow | deny | require_approval

Do NOT emit a tests section and do NOT emit a semantic_guard section.

Each rule carries one effect out of exactly: allow, deny, require_approval.
Rules for routine, read-only, or plainly safe operations should use allow.
Rules for consequential, destructive, production, or sensitive operations MUST
use require_approval and add:
      approval:
        approver_groups: ["maintainers"]
        quorum: 1
        ttl: 5m
        allow_scope: exact_request
The policy defaults to deny, so every operation the user wants permitted must
be covered by an explicit allow or require_approval rule.

Only mention providers, operations, environments, and resources the user
explicitly names. Never invent platforms, permissions, or scopes. When the
user is ambiguous, prefer the stricter resolve (require_approval) and never
write a rule that allows something destructive without approval.

A when expression is optional CEL and may reference resource.environment,
resource.attributes, arguments, and principal.groups. Keep expressions simple
and valid.`

// PromptFor renders the user-facing message from a permissions statement.
func PromptFor(statement string) string {
	var sb strings.Builder
	sb.WriteString(`Translate the following permissions into an offense.dev/raid PolicyBundle YAML document.`)
	sb.WriteByte('\n')
	sb.WriteByte('\n')
	sb.WriteString(statement)
	return sb.String()
}

// ChatBody builds an OpenAI-compatible chat/completions JSON request body.
func ChatBody(model, statement string) []byte {
	if model == "" {
		model = DefaultModel
	}
	var sb strings.Builder
	sb.WriteString(`{"model":`)
	canonical.WriteEscaped(&sb, model)
	sb.WriteString(`,"messages":[`)
	sb.WriteString(`{"role":"system","content":`)
	canonical.WriteEscaped(&sb, systemPrompt)
	sb.WriteString(`},{"role":"user","content":`)
	canonical.WriteEscaped(&sb, PromptFor(statement))
	sb.WriteString(`}],"temperature":0}`)
	return []byte(sb.String())
}

// Transport is the injectable outbound-HTTP seam (unit tests use a scripted
// transport; no network is required).
type Transport interface {
	PostJSON(url, apiKey string, body []byte, deadlineNs int64) (int, []byte, error)
}

var globalTransport Transport

// SetTransport installs a transport (defaults to the network client).
func SetTransport(t Transport) { globalTransport = t }

// netClient is the default transport: a real HTTPS POST to the configured
// endpoint (OpenRouter by default), with a bounded deadline and response size.
// It fails closed on any transport or read failure; the API key is only ever
// sent to the endpoint the caller selected.
type netClient struct{}

// maxTransportBytes caps an OpenRouter response body read (defensive).
const maxTransportBytes = int64(4 << 20)

func (n *netClient) PostJSON(url, apiKey string, body []byte, deadlineNs int64) (int, []byte, error) {
	if deadlineNs <= 0 {
		deadlineNs = DefaultDeadlineNs
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadlineNs))
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, errors.New("raid: openrouter request: " + err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Title", "Raid")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, errors.New("raid: openrouter transport: " + err.Error())
	}
	defer resp.Body.Close()
	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxTransportBytes))
	if rerr != nil {
		return 0, nil, errors.New("raid: openrouter read: " + rerr.Error())
	}
	return resp.StatusCode, data, nil
}

// Translate drafts policy YAML for a permissions statement. The returned text
// is unvalidated: callers MUST run it through policy.LoadBundle and
// policy.CompileBundle before emitting or activating it.
func Translate(t Transport, opts TranslateOptions, statement string) (string, error) {
	if strings.Trim(statement, "\t\r\n ") == "" {
		return "", errors.New("raid: empty permissions statement")
	}
	if opts.ApiKey == "" {
		return "", errors.New("raid: openrouter api key required (set " + KeyEnv + " or pass --key)")
	}
	model := opts.Model
	if model == "" {
		model = DefaultModel
	}
	endpoint := opts.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	ns := opts.DeadlineNs
	if ns <= 0 {
		ns = DefaultDeadlineNs
	}
	body := ChatBody(model, statement)
	client := t
	if client == nil {
		client = &netClient{}
	}
	status, resp, err := client.PostJSON(endpoint, opts.ApiKey, body, ns)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", errors.New("raid: openrouter http status " + strconv.FormatInt(int64(status), 10))
	}
	yamlText, yerr := ExtractPolicyYaml(resp)
	if yerr != nil {
		return "", yerr
	}
	if strings.Trim(yamlText, "\t\r\n ") == "" {
		return "", errors.New("raid: openrouter returned no policy")
	}
	return yamlText, nil
}

// ExtractPolicyYaml pulls the assistant's YAML out of a chat/completions
// response, defensively stripping any markdown fence the model may add.
func ExtractPolicyYaml(resp []byte) (string, error) {
	v, perr := canonical.Decode(resp, canonical.DecodeOptions{MaxBytes: 2 * 1024 * 1024})
	if perr != nil {
		return "", errors.New("raid: openrouter: invalid json response")
	}
	if v.Kind() != canonical.VObject {
		return "", errors.New("raid: openrouter: response is not an object")
	}
	choices, ok := v.AsMap()["choices"]
	if !ok || choices.Kind() != canonical.VList || len(choices.AsList()) == 0 {
		return "", errors.New("raid: openrouter: response missing choices")
	}
	msg, mok := choices.AsList()[0].AsMap()["message"]
	if !mok || msg.Kind() != canonical.VObject {
		return "", errors.New("raid: openrouter: response missing message")
	}
	content, cok := msg.AsMap()["content"]
	if !cok || content.Kind() != canonical.VString {
		return "", errors.New("raid: openrouter: response missing content")
	}
	return stripFence(content.AsString()), nil
}

// stripFence removes a ```yaml ... ``` markdown fence if the model added one.
func stripFence(s string) string {
	trimmed := strings.Trim(s, "\t\r\n ")
	if !strings.HasPrefix(trimmed, "```") {
		return trimmed
	}
	body := trimmed
	if strings.HasPrefix(body, "```") {
		body = strings.TrimPrefix(body, "```")
		if i := strings.IndexRune(body, '\n'); i >= 0 {
			body = body[i+1:]
		}
	}
	if strings.HasSuffix(body, "```") {
		body = strings.TrimSuffix(body, "```")
	}
	return strings.Trim(body, "\t\r\n ")
}

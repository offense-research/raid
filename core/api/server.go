// Raid HTTP/Unix-socket API (spec section 10).
//
// The server is a thin transport over the decision engine and approval
// service. It never constructs an allow decision itself and never exposes
// raw CEL errors, Jev bodies, or policy internals.
package api

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"offense.dev/raid/core/approval"
	"offense.dev/raid/core/audit"
	"offense.dev/raid/core/authn"
	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/decision"
	"offense.dev/raid/core/jev"
	"offense.dev/raid/core/policy"
	"offense.dev/raid/core/signing"
	"offense.dev/raid/core/store"
	"offense.dev/raid/core/stream"
	"offense.dev/raid/core/util"
)

// Config wires the server.
type Config struct {
	Engine     *decision.Engine
	Approvals  *approval.Service
	Store      *store.Store
	Hub        *stream.Hub
	Key        *signing.KeyPair
	Approvers  *authn.ApproverStore
	AllowUIDs  []int64
	MaxBody    int64
	// Evaluator is the optional semantic evaluator (nil disables Jev).
	Evaluator  jev.SemanticEvaluator
}

// Server serves the Raid API.
type Server struct {
	cfg Config
}

// NewServer wires the API server.
func NewServer(cfg Config) *Server {
	if cfg.MaxBody == 0 {
		cfg.MaxBody = canonical.MaxRequestBytes + 65536
	}
	return &Server{cfg: cfg}
}

// Handler returns the routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decisions", s.handleDecisions)
	mux.HandleFunc("/v1/decisions/", s.handleDecisionSub)
	mux.HandleFunc("/v1/approvals", s.handleApprovals)
	mux.HandleFunc("/v1/approvals/", s.handleApprovalSub)
	mux.HandleFunc("/v1/receipts/", s.handleReceiptSub)
	mux.HandleFunc("/v1/policies/active", s.handlePoliciesActive)
	mux.HandleFunc("/v1/policies/validate", s.handlePoliciesValidate)
	mux.HandleFunc("/v1/policies/activate", s.handlePoliciesActivate)
	mux.HandleFunc("/v1/keys", s.handleKeys)
	mux.HandleFunc("/v1/journal", s.handleJournal)
	mux.HandleFunc("/v1/grants", s.handleGrants)
	return mux
}

// ServeUnix serves on a Unix socket, validating peer UIDs.
func (s *Server) ServeUnix(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	addr := &net.UnixAddr{Name: path, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: s.Handler()}
	return httpSrv.Serve(ln)
}

// ServeTCP serves on a TCP address (remote self-hosted mode).
func (s *Server) ServeTCP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	httpSrv := &http.Server{Handler: s.Handler()}
	return httpSrv.Serve(ln)
}

// --- request plumbing ---

func (s *Server) readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBody))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > s.cfg.MaxBody {
		return nil, errors.New("raid: request too large")
	}
	return body, nil
}

func (s *Server) reqID(r *http.Request) string {
	return util.NewID("srv")
}

func (s *Server) writeJSON(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// --- decisions ---

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	body, rerr := s.readBody(r)
	if rerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "could not read request body", false, s.reqID(r)))
		return
	}
	req, perr := canonical.DecodeRequest(body)
	if perr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "invalid request: "+perr.Message(), false, s.reqID(r)))
		return
	}
	d := s.cfg.Engine.Evaluate(req)
	now := time.Now().UTC()
	// optional semantic guard (spec 7.6): deterministic first, monotonic only
	var guard *policy.CompiledGuard
	if active := s.cfg.Engine.Active(); active != nil {
		guard = active.Guard()
	}
	if guard != nil && s.cfg.Evaluator != nil {
		nd, _, serr := decision.ApplySemantic(d, guard, s.cfg.Evaluator, req)
		if serr != nil {
			s.writeJSON(w, http.StatusServiceUnavailable, errDoc(CodeUnavailable, "semantic evaluation unavailable", true, s.reqID(r)))
			return
		}
		d = nd
	}
	switch d.Effect() {
	case "require_approval":
		cfg := d.ApprovalConfig()
		if cfg == nil {
			// Jev escalated an allow with no policy rule: use the
			// fail-safe approval configuration (spec 7.6 outcome).
			cfg = policy.DefaultApprovalConfig()
		}
		// A scoped approval (operation/session) authorizes later matching
		// requests without a fresh approval. Exact-request never short-circuits.
		if cfg.AllowScope() != "" && cfg.AllowScope() != "exact_request" {
			if g, gerr := s.cfg.Approvals.FindGrant(
				req.Principal().SubjectID(), req.Principal().AgentID(), req.Principal().SessionID(),
				req.Action().Operation(), req.Resource().Environment(), d.PolicyBundleHash()); gerr == nil && g != nil {
				d = d.WithGrantCoverage(g.ID())
				if err := audit.WriteDecision(s.cfg.Store, d, now); err != nil {
					s.writeJSON(w, http.StatusServiceUnavailable, errDoc(CodeUnavailable, "decision could not be persisted", true, s.reqID(r)))
					return
				}
				s.writeJSON(w, http.StatusOK, d.WriteJSONString())
				return
			}
		}
		appr, cerr := s.cfg.Approvals.Create(d, req, cfg)
		if cerr != nil {
			s.writeJSON(w, http.StatusServiceUnavailable, errDoc(CodeUnavailable, "approval could not be persisted", true, s.reqID(r)))
			return
		}
		d = d.WithApproval(decision.NewApprovalReference(appr.ID(), string(appr.State()), appr.ExpiresAt()))
		s.writeJSON(w, http.StatusOK, d.WriteJSONString())
	case "deny", "allow":
		if err := audit.WriteDecision(s.cfg.Store, d, now); err != nil {
			s.writeJSON(w, http.StatusServiceUnavailable, errDoc(CodeUnavailable, "decision could not be persisted", true, s.reqID(r)))
			return
		}
		s.writeJSON(w, http.StatusOK, d.WriteJSONString())
	default:
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "unexpected decision", false, s.reqID(r)))
	}
}

func (s *Server) handleDecisionSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/decisions/")
	if strings.HasSuffix(rest, "/wait") {
		id := strings.TrimSuffix(rest, "/wait")
		s.handleDecisionWait(w, r, id)
		return
	}
	s.handleDecisionGet(w, r, rest)
}

func (s *Server) handleDecisionGet(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	var effect, reason, bundleID string
	var approvalID string
	var hash, bhash []byte
	var createdNs, expiresNs, micros int64
	var matched string
	err := s.cfg.Store.QueryRow(`
		SELECT effect, reason_code, request_hash, policy_bundle_id, policy_bundle_hash,
		       matched_rule_ids, approval_id, created_at_ns, expires_at_ns, evaluation_micros
		FROM decisions WHERE id = ?`, id).
		Scan(&effect, &reason, &hash, &bundleID, &bhash, &matched, &approvalID, &createdNs, &expiresNs, &micros)
	if err != nil {
		s.writeJSON(w, http.StatusNotFound, errDoc(CodeApprovalNotFound, "decision not found", false, s.reqID(r)))
		return
	}
	var sb strings.Builder
	sb.WriteString(`{"id":`)
	canonical.WriteEscaped(&sb, id)
	sb.WriteString(`,"effect":`)
	canonical.WriteEscaped(&sb, effect)
	sb.WriteString(`,"reason_code":`)
	canonical.WriteEscaped(&sb, reason)
	sb.WriteString(`,"request_hash":`)
	canonical.WriteEscaped(&sb, canonical.RequestHashString(hash))
	sb.WriteString(`,"policy_bundle_id":`)
	canonical.WriteEscaped(&sb, bundleID)
	sb.WriteString(`,"policy_bundle_hash":`)
	canonical.WriteEscaped(&sb, canonical.RequestHashString(bhash))
	sb.WriteString(`,"matched_rule_ids":`)
	writeStringList(&sb, strings.Split(matched, ","))
	if approvalID != "" {
		sb.WriteString(`,"approval_id":`)
		canonical.WriteEscaped(&sb, approvalID)
	}
	sb.WriteString(`,"evaluated_at":`)
	canonical.WriteEscaped(&sb, time.Unix(0, createdNs).UTC().Format(time.RFC3339))
	sb.WriteString(`,"expires_at":`)
	canonical.WriteEscaped(&sb, time.Unix(0, expiresNs).UTC().Format(time.RFC3339))
	sb.WriteString(`,"evaluation_micros":`)
	sb.WriteString(fmt.Sprintf("%d", micros))
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// handleDecisionWait long-polls an approval to a terminal or approved state.
func (s *Server) handleDecisionWait(w http.ResponseWriter, r *http.Request, decisionID string) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	// bounded long polling: max 30s server-side (spec 10.5)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		appr, err := s.cfg.Approvals.ByDecision(decisionID)
		if err == nil && appr != nil {
			state := appr.State()
			if state == approval.StateApproved || approval.IsTerminal(state) {
				s.writeApprovalState(w, appr)
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	// timeout returns the current state, not an error
	appr, err := s.cfg.Approvals.ByDecision(decisionID)
	if err == nil && appr != nil {
		s.writeApprovalState(w, appr)
		return
	}
	s.writeJSON(w, http.StatusOK, `{"state":"pending","waiting":true}`)
}

func (s *Server) writeApprovalState(w http.ResponseWriter, appr *approval.Approval) {
	var sb strings.Builder
	sb.WriteString(`{"approval_id":`)
	canonical.WriteEscaped(&sb, appr.ID())
	sb.WriteString(`,"state":`)
	canonical.WriteEscaped(&sb, string(appr.State()))
	sb.WriteString(`,"version":`)
	sb.WriteString(fmt.Sprintf("%d", appr.Version()))
	sb.WriteString(`,"expires_at":`)
	canonical.WriteEscaped(&sb, appr.ExpiresAt().Format(time.RFC3339))
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// --- approvals ---

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	list, err := s.cfg.Approvals.ListPending()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "could not list approvals", true, s.reqID(r)))
		return
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, a := range list {
		if i > 0 {
			sb.WriteByte(',')
		}
		a.WriteJSON(&sb)
	}
	sb.WriteByte(']')
	s.writeJSON(w, http.StatusOK, sb.String())
}

func (s *Server) handleApprovalSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/approvals/")
	switch {
	case rest == "stream":
		s.handleStream(w, r)
		return
	case strings.HasSuffix(rest, "/approve"):
		s.handleApprovalResolve(w, r, strings.TrimSuffix(rest, "/approve"), true)
		return
	case strings.HasSuffix(rest, "/deny"):
		s.handleApprovalResolve(w, r, strings.TrimSuffix(rest, "/deny"), false)
		return
	case strings.HasSuffix(rest, "/cancel"):
		s.handleApprovalCancel(w, r, strings.TrimSuffix(rest, "/cancel"))
		return
	default:
		s.handleApprovalGet(w, r, rest)
	}
}

func (s *Server) handleApprovalGet(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	appr, err := s.cfg.Approvals.Get(id)
	if err != nil {
		s.writeJSON(w, http.StatusNotFound, errDoc(CodeApprovalNotFound, "approval not found", false, s.reqID(r)))
		return
	}
	var sb strings.Builder
	appr.WriteJSON(&sb)
	s.writeJSON(w, http.StatusOK, sb.String())
}

func (s *Server) handleApprovalResolve(w http.ResponseWriter, r *http.Request, id string, approve bool) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	body, rerr := s.readBody(r)
	if rerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "could not read request body", false, s.reqID(r)))
		return
	}
	m, err := parseJSON(body)
	if err != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "invalid body", false, s.reqID(r)))
		return
	}
	var expectedVersion uint64
	if x, ok := m["expected_version"]; ok {
		switch x.Kind() {
		case canonical.VInt64:
			if x.AsInt() >= 0 {
				expectedVersion = uint64(x.AsInt())
			}
		case canonical.VUint64:
			expectedVersion = x.AsUint()
		}
	}
	approver := s.resolveApprover(r)
	if !approver.Active {
		s.writeJSON(w, http.StatusUnauthorized, errDoc(CodeUnauthorized, "approver not authorized", false, s.reqID(r)))
		return
	}
	// A06: policy changed while pending -> supersede, never resolve
	if err := s.checkPolicyUnchanged(id); err != nil {
		s.writeJSON(w, http.StatusConflict, errDoc(CodeApprovalConflict, "policy changed while approval pending", false, s.reqID(r)))
		return
	}
	appr, receipt, claims, err := s.cfg.Approvals.Resolve(id, approve, toApprovalApprover(approver), expectedVersion)
	if err != nil {
		s.writeApprovalError(w, err, s.reqID(r))
		return
	}
	var sb strings.Builder
	sb.WriteString(`{"approval":`)
	appr.WriteJSON(&sb)
	if receipt != nil {
		sb.WriteString(`,"receipt":`)
		receipt.WriteReceiptJSON(&sb, claims)
	}
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// checkPolicyUnchanged supersedes approvals whose bundle changed (A06).
func (s *Server) checkPolicyUnchanged(approvalID string) error {
	appr, err := s.cfg.Approvals.Get(approvalID)
	if err != nil {
		return err
	}
	active := s.cfg.Engine.Active()
	if active == nil || !canonical.RequestHashEquals(appr.PolicyBundleHash(), active.Hash()) {
		_, _ = s.cfg.Store.Exec(`UPDATE approvals SET state = 'superseded', version = version + 1, resolved_at_ns = ?
			WHERE id = ? AND state = 'pending'`, time.Now().UTC().UnixNano(), approvalID)
		return fmt.Errorf("policy changed")
	}
	return nil
}

func (s *Server) handleApprovalCancel(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	body, rerr := s.readBody(r)
	if rerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "could not read request body", false, s.reqID(r)))
		return
	}
	cm, cerr := parseJSON(body)
	sessionID := ""
	if cerr == nil {
		if x, ok := cm["session_id"]; ok && x.Kind() == canonical.VString {
			sessionID = x.AsString()
		}
	}
	if sessionID == "" {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "session_id required", false, s.reqID(r)))
		return
	}
	if err := s.cfg.Approvals.Cancel(id, sessionID); err != nil {
		s.writeApprovalError(w, err, s.reqID(r))
		return
	}
	s.writeJSON(w, http.StatusOK, `{"cancelled":true}`)
}

// --- receipts ---

func (s *Server) handleReceiptSub(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/receipts/")
	if !strings.HasSuffix(id, "/consume") {
		s.writeJSON(w, http.StatusNotFound, errDoc(CodeApprovalNotFound, "not found", false, s.reqID(r)))
		return
	}
	id = strings.TrimSuffix(id, "/consume")
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	body, rerr := s.readBody(r)
	if rerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "could not read request body", false, s.reqID(r)))
		return
	}
	cm, cerr := parseJSON(body)
	consumer := ""
	if cerr == nil {
		if x, ok := cm["consumer"]; ok && x.Kind() == canonical.VString {
			consumer = x.AsString()
		}
	}
	if consumer == "" {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "consumer required", false, s.reqID(r)))
		return
	}
	if err := s.cfg.Approvals.Consume(id, consumer); err != nil {
		if err == approval.ErrAlreadyConsumed {
			s.writeJSON(w, http.StatusConflict, errDoc(CodeApprovalConflict, "receipt already consumed", false, s.reqID(r)))
			return
		}
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "consume failed", true, s.reqID(r)))
		return
	}
	s.writeJSON(w, http.StatusOK, `{"consumed":true}`)
}

// --- policies ---

func (s *Server) handlePoliciesActive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	b := s.cfg.Engine.Active()
	if b == nil {
		s.writeJSON(w, http.StatusOK, `{"active":false}`)
		return
	}
	var sb strings.Builder
	sb.WriteString(`{"active":true,"id":`)
	canonical.WriteEscaped(&sb, b.ID())
	sb.WriteString(`,"name":`)
	canonical.WriteEscaped(&sb, b.Name())
	sb.WriteString(`,"revision":`)
	sb.WriteString(fmt.Sprintf("%d", b.Revision()))
	sb.WriteString(`,"hash":`)
	canonical.WriteEscaped(&sb, canonical.RequestHashString(b.Hash()))
	sb.WriteString(`,"rules":`)
	sb.WriteString(fmt.Sprintf("%d", len(b.Rules())))
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

func (s *Server) handlePoliciesValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	body, rerr := s.readBody(r)
	if rerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "could not read request body", false, s.reqID(r)))
		return
	}
	schema, lerr := policy.LoadBundle(body, "api")
	if lerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "invalid policy: "+lerr.Error(), false, s.reqID(r)))
		return
	}
	compiled, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "policy does not compile: "+cerr.Error(), false, s.reqID(r)))
		return
	}
	var sb strings.Builder
	sb.WriteString(`{"valid":true,"id":`)
	canonical.WriteEscaped(&sb, compiled.ID())
	sb.WriteString(`,"hash":`)
	canonical.WriteEscaped(&sb, canonical.RequestHashString(compiled.Hash()))
	sb.WriteString(`,"rules":`)
	sb.WriteString(fmt.Sprintf("%d", len(compiled.Rules())))
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// handleJournal returns a merged, time-ordered activity log of decisions,
// approvals, and audit events: the "what did my agent do" view.
func (s *Server) handleJournal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	limit := int64(50)
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, ok := parseUint(v); ok && n > 0 && n <= 1000 {
			limit = int64(n)
		}
	}
	rows, err := s.cfg.Store.Query(`
		SELECT at_ns, kind, id, detail FROM (
			SELECT created_at_ns AS at_ns, 'decision' AS kind, id AS id,
			       effect || ' ' || reason_code AS detail FROM decisions
			UNION ALL
			SELECT created_at_ns, 'approval', id,
			       operation || ' [' || environment || '] ' || state FROM approvals
			UNION ALL
			SELECT created_at_ns, 'audit', id, kind FROM audit_events
		) ORDER BY at_ns DESC LIMIT ?`, limit)
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "could not read journal", true, s.reqID(r)))
		return
	}
	defer rows.Close()
	var sb strings.Builder
	sb.WriteString(`{"entries":[`)
	first := true
	for rows.Next() {
		var atNs int64
		var kind, id, detail string
		if err := rows.Scan(&atNs, &kind, &id, &detail); err != nil {
			s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "could not read journal", true, s.reqID(r)))
			return
		}
		if !first {
			sb.WriteByte(',')
		}
		first = false
		sb.WriteString(`{"at":`)
		canonical.WriteEscaped(&sb, time.Unix(0, atNs).UTC().Format(time.RFC3339))
		sb.WriteString(`,"kind":`)
		canonical.WriteEscaped(&sb, kind)
		sb.WriteString(`,"id":`)
		canonical.WriteEscaped(&sb, id)
		sb.WriteString(`,"detail":`)
		canonical.WriteEscaped(&sb, detail)
		sb.WriteByte('}')
	}
	sb.WriteString(`]}`)
	s.writeJSON(w, http.StatusOK, sb.String())
}

// handleGrants lists unexpired scoped grants.
func (s *Server) handleGrants(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	if s.cfg.Approvals == nil {
		s.writeJSON(w, http.StatusOK, `[]`)
		return
	}
	grants, err := s.cfg.Approvals.ListGrants()
	if err != nil {
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "could not list grants", true, s.reqID(r)))
		return
	}
	var sb strings.Builder
	sb.WriteByte('[')
	for i, g := range grants {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"id":`)
		canonical.WriteEscaped(&sb, g.ID())
		sb.WriteString(`,"approval_id":`)
		canonical.WriteEscaped(&sb, g.ApprovalID())
		sb.WriteString(`,"operation":`)
		canonical.WriteEscaped(&sb, g.Operation())
		sb.WriteString(`,"environment":`)
		canonical.WriteEscaped(&sb, g.Environment())
		sb.WriteString(`,"scope":`)
		canonical.WriteEscaped(&sb, g.Scope())
		sb.WriteString(`,"expires_at":`)
		canonical.WriteEscaped(&sb, g.ExpiresAt().Format(time.RFC3339))
		sb.WriteByte('}')
	}
	sb.WriteByte(']')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// handleKeys exposes the receipt public key to configured clients (14.3).
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	var sb strings.Builder
	sb.WriteString(`{"key_id":`)
	canonical.WriteEscaped(&sb, s.cfg.Key.ID())
	sb.WriteString(`,"public_key":`)
	canonical.WriteEscaped(&sb, hex.EncodeToString(s.cfg.Key.Public()))
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// --- stream ---

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	sub := stream.NewSseSubscriber()
	if err := s.cfg.Hub.Subscribe(sub); err != nil {
		s.writeJSON(w, http.StatusServiceUnavailable, errDoc(CodeUnavailable, "stream unavailable", true, s.reqID(r)))
		return
	}
	defer s.cfg.Hub.Unsubscribe(sub)
	_ = s.writeInitialSnapshot(w, sub)
	stream.StartStream(w, sub, parseLastEventID(r))
}

func (s *Server) writeInitialSnapshot(w http.ResponseWriter, sub *stream.SseSubscriber) error {
	if _, err := w.Write([]byte(`retry: 1000` + "\n\n")); err != nil {
		return err
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	return nil
}

func parseLastEventID(r *http.Request) uint64 {
	v := r.Header.Get("Last-Event-ID")
	if v == "" {
		return 0
	}
	n, ok := parseUint(v)
	if !ok {
		return 0
	}
	return n
}

func parseUint(v string) (uint64, bool) {
	n := uint64(0)
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n * 10 + uint64(c - '0')
	}
	return n, true
}

// toApprovalApprover adapts the resolved authn approver to the service type.
func toApprovalApprover(a authn.Approver) approval.Approver {
	return approval.Approver{SubjectID: a.SubjectID, Groups: a.Groups, Active: a.Active}
}

// handlePoliciesActivate activates a candidate bundle. Admin-only: the
// approver must be active and belong to the admins group (spec 17, RAID-SEC-011).
func (s *Server) handlePoliciesActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeJSON(w, http.StatusMethodNotAllowed, errDoc(CodeInputInvalid, "method not allowed", false, s.reqID(r)))
		return
	}
	approver := s.resolveApprover(r)
	if !approver.Active || !approver.HasGroup("admins") {
		s.writeJSON(w, http.StatusForbidden, errDoc(CodeUnauthorized, "policy activation requires an admin approver", false, s.reqID(r)))
		return
	}
	body, rerr := s.readBody(r)
	if rerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "could not read request body", false, s.reqID(r)))
		return
	}
	schema, lerr := policy.LoadBundle(body, "api")
	if lerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "invalid policy: "+lerr.Error(), false, s.reqID(r)))
		return
	}
	compiled, cerr := policy.CompileBundle(schema, policy.CompileOptions{})
	if cerr != nil {
		s.writeJSON(w, http.StatusBadRequest, errDoc(CodeInputInvalid, "policy does not compile: "+cerr.Error(), false, s.reqID(r)))
		return
	}
	now := time.Now().UTC()
	if _, err := s.cfg.Store.Exec(`INSERT INTO policy_bundles (id, name, revision, bundle_hash, active, activated_at_ns)
		VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT(id) DO UPDATE SET active = 1, bundle_hash = excluded.bundle_hash`,
		compiled.ID(), compiled.Name(), compiled.Revision(), compiled.Hash(), now.UnixNano()); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "activation storage failed", true, s.reqID(r)))
		return
	}
	if _, err := s.cfg.Store.Exec(`UPDATE policy_bundles SET active = 0 WHERE id != ?`, compiled.ID()); err != nil {
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "activation storage failed", true, s.reqID(r)))
		return
	}
	s.cfg.Engine.Activate(compiled)
	s.cfg.Hub.Publish(stream.Event{Kind: "policy.activated", ApprovalID: compiled.ID(), At: now})
	var sb strings.Builder
	sb.WriteString(`{"activated":true,"id":`)
	canonical.WriteEscaped(&sb, compiled.ID())
	sb.WriteString(`,"hash":`)
	canonical.WriteEscaped(&sb, canonical.RequestHashString(compiled.Hash()))
	sb.WriteByte('}')
	s.writeJSON(w, http.StatusOK, sb.String())
}

// --- helpers ---

func (s *Server) resolveApprover(r *http.Request) authn.Approver {
	subject := r.Header.Get("X-Raid-Approver")
	if subject == "" {
		return authn.Approver{}
	}
	return s.cfg.Approvers.Get(subject)
}

func (s *Server) writeApprovalError(w http.ResponseWriter, err error, reqID string) {
	switch {
	case err == approval.ErrNotFound:
		s.writeJSON(w, http.StatusNotFound, errDoc(CodeApprovalNotFound, "approval not found", false, reqID))
	case err == approval.ErrNotPending || err == approval.ErrTerminal:
		s.writeJSON(w, http.StatusConflict, errDoc(CodeApprovalConflict, "approval is not pending", false, reqID))
	case err == approval.ErrVersionConflict:
		s.writeJSON(w, http.StatusConflict, errDoc(CodeApprovalConflict, "optimistic concurrency conflict", false, reqID))
	case err == approval.ErrExpired:
		s.writeJSON(w, http.StatusConflict, errDoc(CodeApprovalExpired, "approval expired", false, reqID))
	case err == approval.ErrUnauthorized || err == approval.ErrSelfApproval:
		s.writeJSON(w, http.StatusForbidden, errDoc(CodeUnauthorized, "approver not authorized", false, reqID))
	default:
		s.writeJSON(w, http.StatusInternalServerError, errDoc(CodeInternal, "resolution failed", true, reqID))
	}
}

func writeStringList(sb *strings.Builder, items []string) {
	sb.WriteByte('[')
	for i, it := range items {
		if i > 0 {
			sb.WriteByte(',')
		}
		canonical.WriteEscaped(sb, it)
	}
	sb.WriteByte(']')
}

func parseJSON(body []byte) (map[string]canonical.Value, error) {
	v, perr := canonical.Decode(body, canonical.DecodeOptions{MaxBytes: 65536})
	if perr != nil {
		return nil, perr
	}
	if v.Kind() != canonical.VObject {
		return nil, fmt.Errorf("expected object")
	}
	return v.AsMap(), nil
}

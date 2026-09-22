// Package canonical implements the normalized Raid action request model and
// strict decoding of untrusted JSON into it.
package canonical

import (
	"strings"
	"time"
)

// Effect class constants shared by policy, decisions, and approvals.
const (
	EAllow           string = "allow"
	EDeny            string = "deny"
	ERequireApproval string = "require_approval"
)

// ValidEffectClasses are the closed set of effect classes.
var ValidEffectClasses = map[string]bool{
	"read":    true,
	"write":   true,
	"delete":  true,
	"execute": true,
	"admin":   true,
}

// SchemaVersion is the request schema version accepted by this build.
const SchemaVersion = uint32(1)

// Principal identifies the requesting subject, agent session, and groups.
type Principal struct {
	subjectID string
	agentID   string
	sessionID string
	runtime   string
	groups    []string
	trustLevel string
	revision  uint64
}

// Action is the normalized operation being requested.
type Action struct {
	provider  string
	operation string
	effect    string // read | write | delete | execute | admin
}

// Resource is the object the action targets.
type Resource struct {
	typ         string
	id          string
	environment string
	attributes  map[string]string
}

// EvaluationContext carries policy-relevant caller context.
type EvaluationContext struct {
	timestamp       time.Time
	hasTimestamp    bool
	sourceProduct   string
	sourceVersion   string
	sourceRequestID string
	taskSummary     string
	interactive     bool
}

// ActionRequest is the fully normalized, decoded request.
type ActionRequest struct {
	schemaVersion uint32
	requestID     string
	principal     Principal
	action        Action
	resource      Resource
	arguments     map[string]Value
	context       EvaluationContext
}

// MaxRequestBytes bounds untrusted request bodies (spec: request too large).
const MaxRequestBytes = int64(1 * 1024 * 1024)

// MaxArgumentDepth bounds arguments nesting.
const MaxArgumentDepth = int64(32)

// --- Principal accessors ---
func (p Principal) SubjectID() string    { return p.subjectID }
func (p Principal) AgentID() string      { return p.agentID }
func (p Principal) SessionID() string    { return p.sessionID }
func (p Principal) Runtime() string      { return p.runtime }
func (p Principal) Groups() []string     { return p.groups }
func (p Principal) TrustLevel() string   { return p.trustLevel }
func (p Principal) Revision() uint64     { return p.revision }

// --- Action accessors ---
func (a Action) Provider() string     { return a.provider }
func (a Action) Operation() string    { return a.operation }
func (a Action) Effect() string       { return a.effect }

// --- Resource accessors ---
func (r Resource) Type() string                 { return r.typ }
func (r Resource) ID() string                   { return r.id }
func (r Resource) Environment() string          { return r.environment }
func (r Resource) Attributes() map[string]string { return r.attributes }

// --- Context accessors ---
func (c EvaluationContext) Timestamp() (time.Time, bool)    { return c.timestamp, c.hasTimestamp }
func (c EvaluationContext) SourceProduct() string           { return c.sourceProduct }
func (c EvaluationContext) SourceVersion() string           { return c.sourceVersion }
func (c EvaluationContext) SourceRequestID() string         { return c.sourceRequestID }
func (c EvaluationContext) TaskSummary() string             { return c.taskSummary }
func (c EvaluationContext) Interactive() bool               { return c.interactive }

// --- Request accessors ---
func (r *ActionRequest) SchemaVersion() uint32              { return r.schemaVersion }
func (r *ActionRequest) RequestID() string                  { return r.requestID }
func (r *ActionRequest) Principal() Principal               { return r.principal }
func (r *ActionRequest) Action() Action                     { return r.action }
func (r *ActionRequest) Resource() Resource                 { return r.resource }
func (r *ActionRequest) Arguments() map[string]Value { return r.arguments }
func (r *ActionRequest) Context() EvaluationContext         { return r.context }

// DecodeRequest strictly decodes a JSON action request document.
// Unknown fields, malformed values, and unsupported schema versions are
// rejected with a precise path. This is the normalization boundary between
// untrusted callers and the decision engine.
func DecodeRequest(data []byte) (*ActionRequest, *ParseError) {
	root, err := Decode(data, DecodeOptions{
		MaxBytes: MaxRequestBytes,
		MaxDepth: MaxArgumentDepth,
	})
	if err != nil {
		return nil, err
	}
	return DecodeRequestValue(root)
}

// DecodeRequestValue decodes a request from an already-parsed JSON object.
func DecodeRequestValue(root Value) (*ActionRequest, *ParseError) {
	if root.Kind() != VObject {
		return nil, NewError("request must be a JSON object", "", root.AsPos())
	}
	obj := root.AsMap()
	var req ActionRequest
	var err *ParseError
	for key, val := range obj {
		switch key {
		case "schema_version":
			if val.Kind() != VInt64 && val.Kind() != VUint64 {
				return nil, reqErr("schema_version must be an integer", key)
			}
			n := valNum(val)
			if n < 0 || uint64(n) != uint64(uint32(n)) {
				return nil, reqErr("schema_version out of range", key)
			}
			sv := uint32(n)
			if sv != SchemaVersion {
				return nil, reqErr("unsupported schema_version", key)
			}
			req.schemaVersion = sv
		case "request_id":
			s, err := reqString(val, key)
			if err != nil {
				return nil, err
			}
			req.requestID = s
		case "principal":
			if val.Kind() != VObject {
				return nil, reqErr("principal must be an object", key)
			}
			req.principal, err = decodePrincipal(val)
			if err != nil {
				return nil, err
			}
		case "action":
			if val.Kind() != VObject {
				return nil, reqErr("action must be an object", key)
			}
			req.action, err = decodeAction(val)
			if err != nil {
				return nil, err
			}
		case "resource":
			if val.Kind() != VObject {
				return nil, reqErr("resource must be an object", key)
			}
			req.resource, err = decodeResource(val)
			if err != nil {
				return nil, err
			}
		case "arguments":
			if val.Kind() != VObject {
				return nil, reqErr("arguments must be an object", key)
			}
			args := map[string]Value{}
			for k, av := range val.AsMap() {
				norm, err := NormalizeArg(av)
				if err != nil {
					return nil, err
				}
				args[k] = norm
			}
			req.arguments = args
		case "context":
			if val.Kind() != VObject {
				return nil, reqErr("context must be an object", key)
			}
			req.context, err = decodeContext(val)
			if err != nil {
				return nil, err
			}
		default:
			return nil, reqErr("unknown field", key)
		}
	}
	// Required field validation.
	if req.requestID == "" {
		return nil, NewError("missing required field request_id", "", -1)
	}
	if req.principal.subjectID == "" {
		return nil, NewError("missing required field principal.subject_id", "", -1)
	}
	if req.principal.agentID == "" {
		return nil, NewError("missing required field principal.agent_id", "", -1)
	}
	if req.action.provider == "" {
		return nil, NewError("missing required field action.provider", "", -1)
	}
	if req.action.operation == "" {
		return nil, NewError("missing required field action.operation", "", -1)
	}
	if !isValidOperation(req.action.operation) {
		return nil, NewError("invalid operation format", "action.operation", -1)
	}
	if !ValidEffectClasses[req.action.effect] {
		return nil, NewError("invalid action.effect", "action.effect", -1)
	}
	if req.context.sourceProduct == "" {
		return nil, NewError("missing required field context.source_product", "", -1)
	}
	return &req, nil
}

func reqErr(msg, key string) *ParseError {
	return NewError(msg, key, -1)
}

func valNum(v Value) int64 {
	switch v.Kind() {
	case VInt64:
		return v.AsInt()
	case VUint64:
		if v.AsUint() > uint64(9223372036854775807) {
			return ^int64(0)
		}
		return int64(v.AsUint())
	}
	return -1
}

func reqString(v Value, key string) (string, *ParseError) {
	if v.Kind() != VString {
		return "", NewError("expected string", key, v.AsPos())
	}
	return v.AsString(), nil
}

func decodePrincipal(v Value) (Principal, *ParseError) {
	obj := v.AsMap()
	var p Principal
	var err *ParseError
	for key, val := range obj {
		switch key {
		case "subject_id":
			p.subjectID, err = reqString(val, "principal." + key)
			if err != nil {
				return p, err
			}
		case "agent_id":
			p.agentID, err = reqString(val, "principal." + key)
			if err != nil {
				return p, err
			}
		case "session_id":
			p.sessionID, err = reqString(val, "principal." + key)
			if err != nil {
				return p, err
			}
		case "runtime":
			p.runtime, err = reqString(val, "principal." + key)
			if err != nil {
				return p, err
			}
		case "trust_level":
			p.trustLevel, err = reqString(val, "principal." + key)
			if err != nil {
				return p, err
			}
		case "revision":
			if val.Kind() != VUint64 && val.Kind() != VInt64 {
				return p, NewError("revision must be an integer", "principal.revision", val.AsPos())
			}
			n := valNum(val)
			if n < 0 {
				return p, NewError("revision must be non-negative", "principal.revision", val.AsPos())
			}
			p.revision = uint64(n)
		case "groups":
			if val.Kind() != VList {
				return p, NewError("groups must be a list of strings", "principal.groups", val.AsPos())
			}
gs := []string{}
			for _, g := range val.AsList() {
				if g.Kind() != VString {
					return p, NewError("groups must be a list of strings", "principal.groups", g.AsPos())
				}
				gs = append(gs, g.AsString())
			}
			p.groups = gs
		default:
			return p, NewError("unknown field", "principal." + key, val.AsPos())
		}
	}
	return p, nil
}

func decodeAction(v Value) (Action, *ParseError) {
	obj := v.AsMap()
	var a Action
	var err *ParseError
	for key, val := range obj {
		switch key {
		case "provider":
			a.provider, err = reqString(val, "action." + key)
			if err != nil {
				return a, err
			}
		case "operation":
			a.operation, err = reqString(val, "action." + key)
			if err != nil {
				return a, err
			}
		case "effect":
			a.effect, err = reqString(val, "action." + key)
			if err != nil {
				return a, err
			}
		default:
			return a, NewError("unknown field", "action." + key, val.AsPos())
		}
	}
	return a, nil
}

func decodeResource(v Value) (Resource, *ParseError) {
	obj := v.AsMap()
	var r Resource
	var err *ParseError
	for key, val := range obj {
		switch key {
		case "type":
			r.typ, err = reqString(val, "resource." + key)
			if err != nil {
				return r, err
			}
		case "id":
			r.id, err = reqString(val, "resource." + key)
			if err != nil {
				return r, err
			}
		case "environment":
			r.environment, err = reqString(val, "resource." + key)
			if err != nil {
				return r, err
			}
		case "attributes":
			if val.Kind() != VObject {
				return r, NewError("attributes must be an object", "resource.attributes", val.AsPos())
			}
			attrs := map[string]string{}
			for k, av := range val.AsMap() {
				if av.Kind() != VString {
					return r, NewError("attribute values must be strings", "resource.attributes." + k, av.AsPos())
				}
				attrs[k] = av.AsString()
			}
			r.attributes = attrs
		default:
			return r, NewError("unknown field", "resource." + key, val.AsPos())
		}
	}
	return r, nil
}

func decodeContext(v Value) (EvaluationContext, *ParseError) {
	obj := v.AsMap()
	var c EvaluationContext
	var err *ParseError
	for key, val := range obj {
		switch key {
		case "timestamp":
			if val.Kind() != VString {
				return c, NewError("timestamp must be an RFC3339 string", "context.timestamp", val.AsPos())
			}
			t, terr := time.Parse(time.RFC3339, val.AsString())
			if terr != nil {
				return c, NewError("invalid timestamp format", "context.timestamp", val.AsPos())
			}
			c.timestamp = t
			c.hasTimestamp = true
		case "source_product":
			c.sourceProduct, err = reqString(val, "context." + key)
			if err != nil {
				return c, err
			}
		case "source_version":
			c.sourceVersion, err = reqString(val, "context." + key)
			if err != nil {
				return c, err
			}
		case "source_request_id":
			c.sourceRequestID, err = reqString(val, "context." + key)
			if err != nil {
				return c, err
			}
		case "task_summary":
			c.taskSummary, err = reqString(val, "context." + key)
			if err != nil {
				return c, err
			}
		case "interactive":
			if val.Kind() != VBool {
				return c, NewError("interactive must be boolean", "context.interactive", val.AsPos())
			}
			c.interactive = val.AsBool()
		default:
			return c, NewError("unknown field", "context." + key, val.AsPos())
		}
	}
	return c, nil
}

// NormalizeArg converts a JSON value into the Raid typed Value union.
// A value of the form {"type": "...", "value": ...} is interpreted as the
// normalized typed encoding; any other JSON value is mapped structurally
// onto the closed tagged set. Floats are never produced: fractional numbers
// are preserved as validated decimal text (VDecimal).
func NormalizeArg(v Value) (Value, *ParseError) {
	if v.Kind() == VObject {
		obj := v.AsMap()
		if tv, has := obj["type"]; has && tv.Kind() == VString {
			if len(obj) != 2 {
				return v, NewError("typed argument must contain exactly type and value", "", v.AsPos())
			}
			valv, hasVal := obj["value"]
			if !hasVal {
				return v, NewError("typed argument missing value", "value", v.AsPos())
			}
			return normalizeTyped(tv.AsString(), valv)
		}
	}
	switch v.Kind() {
	case VString, VBool, VInt64, VUint64, VDecimal, VNull:
		return v, nil
	case VList:
		out := List()
		for _, item := range v.AsList() {
			n, err := NormalizeArg(item)
			if err != nil {
				return out, err
			}
			out = AppendList(out, n)
		}
		return out, nil
	case VObject:
		out := Object()
		for k, item := range v.AsMap() {
			n, err := NormalizeArg(item)
			if err != nil {
				return out, err
			}
			out = PutObject(out, k, n)
		}
		return out, nil
	}
	return v, nil
}

func normalizeTyped(t string, v Value) (Value, *ParseError) {
	switch t {
	case "string":
		if v.Kind() != VString {
			return v, NewError("typed string requires a string value", "value", v.AsPos())
		}
		return v, nil
	case "int64":
		if v.Kind() != VInt64 && v.Kind() != VUint64 {
			return v, NewError("typed int64 requires an integer value", "value", v.AsPos())
		}
		return v, nil
	case "uint64":
		if v.Kind() != VUint64 && v.Kind() != VInt64 {
			return v, NewError("typed uint64 requires an integer value", "value", v.AsPos())
		}
		if v.Kind() == VInt64 && v.AsInt() < 0 {
			return v, NewError("typed uint64 requires a non-negative value", "value", v.AsPos())
		}
		return v, nil
	case "bool":
		if v.Kind() != VBool {
			return v, NewError("typed bool requires a boolean value", "value", v.AsPos())
		}
		return v, nil
	case "decimal":
		if v.Kind() != VString || !isValidDecimal(v.AsString()) {
			return v, NewError("typed decimal requires a decimal string value", "value", v.AsPos())
		}
		return Decimal(v.AsString()), nil
	case "timestamp":
		if v.Kind() != VString {
			return v, NewError("typed timestamp requires an RFC3339 string value", "value", v.AsPos())
		}
		if _, terr := time.Parse(time.RFC3339, v.AsString()); terr != nil {
			return v, NewError("typed timestamp is not RFC3339", "value", v.AsPos())
		}
		return Timestamp(v.AsString()), nil
	case "duration":
		if v.Kind() != VString || !isValidDuration(v.AsString()) {
			return v, NewError("typed duration requires a duration string value", "value", v.AsPos())
		}
		return Duration(v.AsString()), nil
	case "list":
		if v.Kind() != VList {
			return v, NewError("typed list requires an array value", "value", v.AsPos())
		}
		return NormalizeArg(v)
	case "map":
		if v.Kind() != VObject {
			return v, NewError("typed map requires an object value", "value", v.AsPos())
		}
		return NormalizeArg(v)
	}
	return v, NewError("unknown typed argument kind", "type", v.AsPos())
}

// isValidDecimal validates the decimal text grammar (no NaN, no floats).
func isValidDecimal(s string) bool {
	return isValidNumberText(s)
}

// isValidNumberText validates JSON number grammar without a leading zero rule.
func isValidNumberText(s string) bool {
	if len(s) == 0 {
		return false
	}
	i := 0
	if s[0] == '-' {
		i++
	}
	digits := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		digits++
	}
	if digits == 0 {
		return false
	}
	if i < len(s) && s[i] == '.' {
		i++
		frac := 0
		for ; i < len(s); i++ {
			c := s[i]
			if c < '0' || c > '9' {
				break
			}
			frac++
		}
		if frac == 0 {
			return false
		}
	}
	if i < len(s) && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < len(s) && (s[i] == '+' || s[i] == '-') {
			i++
		}
		exp := 0
		for ; i < len(s); i++ {
			c := s[i]
			if c < '0' || c > '9' {
				break
			}
			exp++
		}
		if exp == 0 {
			return false
		}
	}
	return i == len(s)
}

// isValidDuration validates duration text like 30s, 5m, 24h.
func isValidDuration(s string) bool {
	i := 0
	n := 0
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		n = n * 10 + int(c - '0')
		if n > 100000000 {
			return false
		}
	}
	if n == 0 || i >= len(s) {
		return false
	}
	unit := s[i:]
	return unit == "ms" || unit == "s" || unit == "m" || unit == "h" || unit == "d"
}

// isValidOperation enforces the operation naming grammar (hard rule).
func isValidOperation(op string) bool {
	if len(op) == 0 || len(op) > 128 {
		return false
	}
	for _, r := range op {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	// must contain a '.' separating provider-qualified operation
	return strings.IndexRune(op, '.') > 0
}
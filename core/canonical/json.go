// Package canonical implements Raid's strict JSON codec and canonical encoding.
//
// The strict decoder is the security boundary for untrusted input: it rejects
// unknown fields, duplicate object keys, malformed numbers, invalid UTF-8,
// excessive depth, and oversized documents with precise error paths.
// Floats are never produced: numbers without a fraction are int64/uint64 and
// numbers with a fraction or exponent are preserved as validated decimal text.
package canonical

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	_ "unsafe"
)

// ValueKind is the closed tag set of JSON values produced by the strict
// decoder. It mirrors the Raid Value union (see core/canonical/action.go).
type ValueKind byte

const (
	VNull      ValueKind = 0
	VBool      ValueKind = 1
	VInt64     ValueKind = 2
	VUint64    ValueKind = 3
	VDecimal   ValueKind = 4 // decimal text with validated syntax (no floats)
	VString    ValueKind = 5
	VList      ValueKind = 6
	VObject    ValueKind = 7
	VTimestamp ValueKind = 8
	VDuration  ValueKind = 9
	VBytes     ValueKind = 10
)

// Value is the tagged union used for request arguments and JSON documents.
// Exactly one of the payload fields is meaningful per Kind.
type Value struct {
	kind  ValueKind
	b     bool
	i     int64
	u     uint64
	s     string
	bytes []byte
	arr   []Value
	obj   map[string]Value
	pos   int64 // source byte offset (diagnostics)
}

func Null() Value              { return Value{kind: VNull} }
func Bool(b bool) Value        { return Value{kind: VBool, b: b} }
func Int(i int64) Value        { return Value{kind: VInt64, i: i} }
func Uint(u uint64) Value      { return Value{kind: VUint64, u: u} }
func Decimal(s string) Value   { return Value{kind: VDecimal, s: s} }
func Str(s string) Value       { return Value{kind: VString, s: s} }
func Timestamp(s string) Value { return Value{kind: VTimestamp, s: s} }
func Duration(s string) Value  { return Value{kind: VDuration, s: s} }
func Bytes(b []byte) Value     { return Value{kind: VBytes, bytes: b} }
func List() Value              { return Value{kind: VList, arr: []Value{}} }
func Object() Value            { return Value{kind: VObject, obj: map[string]Value{}} }

// Kind returns the tagged kind of v.
func (v Value) Kind() ValueKind { return v.kind }

// AsBool returns the boolean payload; valid when Kind() == VBool.
func (v Value) AsBool() bool { return v.b }

// AsInt returns the signed payload; valid when Kind() == VInt64.
func (v Value) AsInt() int64 { return v.i }

// AsUint returns the unsigned payload; valid when Kind() == VUint64.
func (v Value) AsUint() uint64 { return v.u }

// AsString returns the string payload (string, decimal, timestamp, or
// duration text); valid for the corresponding kinds.
func (v Value) AsString() string { return v.s }

// AsList returns the list payload; valid when Kind() == VList.
func (v Value) AsList() []Value { return v.arr }

// AsMap returns the object payload; valid when Kind() == VObject.
func (v Value) AsMap() map[string]Value { return v.obj }

// AsPos returns the source byte offset of the value (diagnostics only).
func (v Value) AsPos() int64 { return v.pos }

// AsTimestampText returns the RFC3339 text payload of a VTimestamp value.
func (v Value) AsTimestampText() string { return v.s }

// AsDurationText returns the duration text payload of a VDuration value.
func (v Value) AsDurationText() string { return v.s }

// ParseError describes a strict decoding failure.
type ParseError struct {
	msg  string
	path string
	pos  int64
}

func (e *ParseError) Error() string {
	if len(e.path) > 0 {
		return fmt.Sprintf("%s at %s (offset %d)", e.msg, e.path, e.pos)
	}
	if e.pos >= 0 {
		return fmt.Sprintf("%s (offset %d)", e.msg, e.pos)
	}
	return e.msg
}

// NewError constructs a decode error with a message, dotted path, and offset.
func NewError(msg, path string, pos int64) *ParseError {
	return &ParseError{msg: msg, path: path, pos: pos}
}

// AppendList returns a copy of list v with item appended (immutable style).
func AppendList(v Value, item Value) Value {
	return Value{kind: VList, arr: append(v.arr, item), pos: v.pos}
}

// PutObject returns a copy of object v with key k mapped to item.
func PutObject(v Value, k string, item Value) Value {
	m := v.obj
	m[k] = item
	return Value{kind: VObject, obj: m, pos: v.pos}
}

// Message returns the unstructured error description.
func (e *ParseError) Message() string { return e.msg }

// Path returns the dotted JSON path where the error occurred (may be empty).
func (e *ParseError) Path() string { return e.path }

// Pos returns the source byte offset (or -1 when unknown).
func (e *ParseError) Pos() int64 { return e.pos }

var errTooLarge = errors.New("raid: json document exceeds size limit")
var errTooDeep = errors.New("raid: json nesting exceeds depth limit")

// DecodeOptions bounds the document; zero limits mean "no explicit bound".
type DecodeOptions struct {
	MaxBytes int64 // maximum document byte length, 0 = unbounded
	MaxDepth int64 // maximum nesting depth, 0 = 128
}

// Decode parses a single JSON document from data.
func Decode(data []byte, opts DecodeOptions) (Value, *ParseError) {
	if opts.MaxBytes > 0 && int64(len(data)) > opts.MaxBytes {
		return Null(), &ParseError{msg: "document exceeds size limit", pos: int64(len(data))}
	}
	if !utf8.Valid(data) {
		return Null(), &ParseError{msg: "document is not valid UTF-8", pos: 0}
	}
	maxDepth := opts.MaxDepth
	if maxDepth == 0 {
		maxDepth = 128
	}
	var p parser
	p.data = data
	p.n = len(data)
	p.depth = 0
	p.maxDepth = maxDepth
	v, err := p.parseValue()
	if err != nil {
		return Null(), err
	}
	p.skipWs()
	if p.i < p.n {
		return Null(), p.fail("trailing content after document", p.i)
	}
	return v, nil
}

type parser struct {
	data     []byte
	n        int
	i        int
	depth    int64
	maxDepth int64
	stack    []string
}

func (p *parser) fail(msg string, pos int) *ParseError {
	return &ParseError{msg: msg, pos: int64(pos)}
}

func (p *parser) peek() (byte, bool) {
	if p.i < p.n {
		return p.data[p.i], true
	}
	return 0, false
}

func (p *parser) skipWs() {
	for ; p.i < p.n; p.i++ {
		c := p.data[p.i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return
		}
	}
}

func (p *parser) depthDown() {
	p.depth--
}

// pathString returns the dotted JSON path of the current location.
func (p *parser) push(k string) {
	p.stack = append(p.stack, k)
}

func (p *parser) pop() {
	p.stack = p.stack[:len(p.stack)-1]
}

func (p *parser) path() string {
	if len(p.stack) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, k := range p.stack {
		if i > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(k)
	}
	return sb.String()
}

func (p *parser) parseValue() (Value, *ParseError) {
	p.skipWs()
	if p.i >= p.n {
		return Null(), p.fail("unexpected end of input", p.i)
	}
	p.depth++
	defer p.depthDown()
	if p.depth > p.maxDepth {
		return Null(), p.fail("nesting exceeds depth limit", p.i)
	}
	c := p.data[p.i]
	switch c {
	case '{':
		return p.parseObject()
	case '[':
		return p.parseArray()
	case '"':
		s, err := p.parseString()
		if err != nil {
			return Null(), err
		}
		return Str(s), nil
	case 't':
		if p.n-p.i >= 4 && string(p.data[p.i:p.i+4]) == "true" {
			p.i += 4
			return Bool(true), nil
		}
		return Null(), p.fail("invalid literal", p.i)
	case 'f':
		if p.n-p.i >= 5 && string(p.data[p.i:p.i+5]) == "false" {
			p.i += 5
			return Bool(false), nil
		}
		return Null(), p.fail("invalid literal", p.i)
	case 'n':
		if p.n-p.i >= 4 && string(p.data[p.i:p.i+4]) == "null" {
			p.i += 4
			return Null(), nil
		}
		return Null(), p.fail("invalid literal", p.i)
	default:
		if c == '-' || (c >= '0' && c <= '9') {
			return p.parseNumber()
		}
		return Null(), p.fail(fmt.Sprintf("unexpected character %q", string([]byte{c})), p.i)
	}
}

func (p *parser) parseObject() (Value, *ParseError) {
	start := p.i
	p.i++ // consume '{'
	v := Object()
	members := map[string]Value{}
	p.skipWs()
	if p.peek2() == '}' {
		p.i++
		v.pos = int64(start)
		return v, nil
	}
	for {
		p.skipWs()
		if p.peek2() != '"' {
			return Null(), p.fail("expected object key string", p.i)
		}
		key, err := p.parseString()
		if err != nil {
			return Null(), err
		}
		if _, dup := members[key]; dup {
			return Null(), p.fail("duplicate object key "+key, p.i)
		}
		p.skipWs()
		if p.peek2() != ':' {
			return Null(), p.fail("expected ':' after object key", p.i)
		}
		p.i++
		p.push(key)
		mv, err := p.parseValue()
		p.pop()
		if err != nil {
			return Null(), err
		}
		members[key] = mv
		p.skipWs()
		c := p.peek2()
		if c == ',' {
			p.i++
			continue
		}
		if c == '}' {
			p.i++
			v.obj = members
			v.pos = int64(start)
			return v, nil
		}
		return Null(), p.fail("expected ',' or '}' in object", p.i)
	}
}

func (p *parser) parseArray() (Value, *ParseError) {
	start := p.i
	p.i++ // consume '['
	v := List()
	items := []Value{}
	p.skipWs()
	if p.peek2() == ']' {
		p.i++
		v.pos = int64(start)
		return v, nil
	}
	for idx := int64(0); ; idx++ {
		p.push(fmt.Sprintf("%d", idx))
		item, err := p.parseValue()
		p.pop()
		if err != nil {
			return Null(), err
		}
		items = append(items, item)
		p.skipWs()
		c := p.peek2()
		if c == ',' {
			p.i++
			continue
		}
		if c == ']' {
			p.i++
			v.arr = items
			v.pos = int64(start)
			return v, nil
		}
		return Null(), p.fail("expected ',' or ']' in array", p.i)
	}
}

// parseString decodes a JSON string at p.data[p.i] (the opening quote).
func (p *parser) parseString() (string, *ParseError) {
	start := p.i
	p.i++ // consume '"'
	var sb strings.Builder
	for {
		if p.i >= p.n {
			return "", p.fail("unterminated string", start)
		}
		c := p.data[p.i]
		switch c {
		case '"':
			p.i++
			return sb.String(), nil
		case '\\':
			p.i++
			if p.i >= p.n {
				return "", p.fail("unterminated escape", start)
			}
			e := p.data[p.i]
			p.i++
			switch e {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case '/':
				sb.WriteByte('/')
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				if p.i+4 > p.n {
					return "", p.fail("truncated unicode escape", start)
				}
				hi, err := p.parseHex4()
				if err != nil {
					return "", err
				}
				if hi >= 0xd800 && hi <= 0xdbff {
					// high surrogate: expect \uXXXX low surrogate
					if p.i+6 <= p.n && p.data[p.i] == '\\' && p.data[p.i+1] == 'u' {
						p.i += 2
						lo, err := p.parseHex4()
						if err != nil {
							return "", err
						}
						if lo < 0xdc00 || lo > 0xdfff {
							return "", p.fail("invalid low surrogate", p.i-4)
						}
						sb.WriteRune(utf16.DecodeRune(rune(hi), rune(lo)))
						continue
					}
					return "", p.fail("unpaired surrogate escape", p.i-4)
				}
				if hi >= 0xdc00 && hi <= 0xdfff {
					return "", p.fail("unpaired surrogate escape", p.i-4)
				}
				sb.WriteRune(rune(hi))
			default:
				return "", p.fail("invalid escape sequence", p.i-1)
			}
		default:
			if c < 0x20 {
				return "", p.fail("unescaped control character in string", p.i)
			}
			sb.WriteByte(c)
			p.i++
		}
	}
}

// parseHex4 reads four hex digits (already positioned at the first digit).
func (p *parser) parseHex4() (uint32, *ParseError) {
	n := uint32(0)
	for k := 0; k < 4; k++ {
		if p.i >= p.n {
			return 0, p.fail("truncated unicode escape", p.i)
		}
		c := p.data[p.i]
		var d uint32
		if c >= '0' && c <= '9' {
			d = uint32(c - '0')
		} else if c >= 'a' && c <= 'f' {
			d = uint32(c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			d = uint32(c - 'A' + 10)
		} else {
			return 0, p.fail("invalid hex digit in unicode escape", p.i)
		}
		n = (n << 4) | d
		p.i++
	}
	return n, nil
}

// parseNumber consumes a JSON number. Validated, no floats.
func (p *parser) parseNumber() (Value, *ParseError) {
	start := p.i
	var isInt bool = true
	if p.data[p.i] == '-' {
		p.i++
	}
	// integer part
	c, ok := p.peek()
	if !ok {
		return Null(), p.fail("truncated number", start)
	}
	if c == '0' {
		p.i++
	} else if c >= '1' && c <= '9' {
		for {
			c, ok := p.peek()
			if !ok || c < '0' || c > '9' {
				break
			}
			p.i++
		}
	} else {
		return Null(), p.fail("invalid number", start)
	}
	// fraction
	if c, ok := p.peek(); ok && c == '.' {
		isInt = false
		p.i++
		c, ok := p.peek()
		if !ok || c < '0' || c > '9' {
			return Null(), p.fail("invalid number fraction", start)
		}
		for {
			c, ok := p.peek()
			if !ok || c < '0' || c > '9' {
				break
			}
			p.i++
		}
	}
	// exponent
	if c, ok := p.peek(); ok && (c == 'e' || c == 'E') {
		isInt = false
		p.i++
		if c, ok := p.peek(); ok && (c == '+' || c == '-') {
			p.i++
		}
		c, ok := p.peek()
		if !ok || c < '0' || c > '9' {
			return Null(), p.fail("invalid number exponent", start)
		}
		for {
			c, ok := p.peek()
			if !ok || c < '0' || c > '9' {
				break
			}
			p.i++
		}
	}
	// validate UTF-8 boundary already guaranteed by byte scanning
	text := string(p.data[start:p.i])
	if isInt {
		if v, err := strconv.ParseInt(text, 10, 64); err == nil {
			return Int(v), nil
		}
		if v, err := strconv.ParseUint(text, 10, 64); err == nil {
			return Uint(v), nil
		}
		return Null(), p.fail("integer out of range", start)
	}
	// decimal: syntax validated above by the scanner; preserve the text.
	return Decimal(text), nil
}

func (p *parser) peek2() byte {
	if p.i < p.n {
		return p.data[p.i]
	}
	return 0
}

// EscapedWrites appends a JSON-escaped string to sb.
func WriteEscaped(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			if r < 0x20 {
				sb.WriteString(fmt.Sprintf(`\u%04x`, uint32(r)))
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// Escape returns the JSON-escaped form of s (no surrounding quotes).
func Escape(s string) string {
	var sb strings.Builder
	WriteEscaped(&sb, s)
	return sb.String()
}

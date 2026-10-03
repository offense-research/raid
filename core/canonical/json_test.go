package canonical_test

import (
	"strings"
	"testing"

	"github.com/offense-research/raid/core/canonical"
)

func TestDecodeScalars(t *testing.T) {
	cases := []string{`null`, `true`, `false`, `42`, `-17`, `0`, `"hi"`}
	for _, c := range cases {
		v, err := canonical.Decode([]byte(c), canonical.DecodeOptions{})
		if err != nil {
			t.Errorf("decode %v: %v", c, err.Error())
		}
		_ = v
	}
}

func TestDecodeIntBounds(t *testing.T) {
	v, err := canonical.Decode([]byte(`9223372036854775807`), canonical.DecodeOptions{})
	if err != nil || v.Kind() != canonical.VInt64 || v.AsInt() != 9223372036854775807 {
		t.Errorf("max int64: got %v err %v", v, err)
	}
	v, err = canonical.Decode([]byte(`18446744073709551615`), canonical.DecodeOptions{})
	if err != nil || v.Kind() != canonical.VUint64 || v.AsUint() != 18446744073709551615 {
		t.Errorf("max uint64: got %v err %v", v, err)
	}
	v, err = canonical.Decode([]byte(`18446744073709551616`), canonical.DecodeOptions{})
	if err == nil {
		t.Errorf("overflow uint64 should fail: %v", v)
	}
}

func TestDecodeDecimalNoFloat(t *testing.T) {
	v, err := canonical.Decode([]byte(`2400.50`), canonical.DecodeOptions{})
	if err != nil || v.Kind() != canonical.VDecimal || v.AsString() != "2400.50" {
		t.Errorf("decimal: got %v err %v", v, err)
	}
	v, err = canonical.Decode([]byte(`1e3`), canonical.DecodeOptions{})
	if err != nil || v.Kind() != canonical.VDecimal || v.AsString() != "1e3" {
		t.Errorf("exponent decimal: got %v err %v", v, err)
	}
}

func TestDecodeObject(t *testing.T) {
	body := `{"a": 1, "b": [true, {"c": "x"}]}`
	v, err := canonical.Decode([]byte(body), canonical.DecodeOptions{})
	if err != nil {
		t.Errorf("object: %v", err.Error())
		return
	}
	if v.Kind() != canonical.VObject || len(v.AsMap()) != 2 {
		t.Errorf("object shape: %v", v)
		return
	}
	inner, ok := v.AsMap()["b"]
	if !ok || inner.Kind() != canonical.VList || len(inner.AsList()) != 2 {
		t.Errorf("nested list: %v", v)
	}
}

func TestDecodeRejects(t *testing.T) {
	bad := []string{
		`{"a": 1, "a": 2}`, // duplicate key
		`{"a":}`,           // missing value
		`[1, 2`,            // unterminated array
		`"abc`,             // unterminated string
		`01`,               // leading zero
		`1.2.3`,            // junk number
		`nan`,              // bad literal
		`{} {}`,            // trailing content
		`"\u00"`,           // truncated escape
		`"\ud800"`,         // unpaired surrogate
		`"\ud800\u0041"`,   // high surrogate + non-low
		`[1,]`,             // trailing comma
		`{"a" 1}`,          // missing colon
		string([]byte{0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xc3, 0x28, 0x22, 0x7d}), // bad UTF-8
	}
	for _, b := range bad {
		v, err := canonical.Decode([]byte(b), canonical.DecodeOptions{})
		if err == nil {
			t.Errorf("should reject %q: got %v", b, v)
		}
	}
}

func TestDecodeRejectsDepth(t *testing.T) {
	depth := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	v, err := canonical.Decode([]byte(depth), canonical.DecodeOptions{MaxDepth: 64})
	if err == nil {
		t.Errorf("depth limit: %v", v)
	}
}

func TestDecodeSizeLimit(t *testing.T) {
	body := `{"padding": "` + strings.Repeat("x", 4000) + `"}`
	v, err := canonical.Decode([]byte(body), canonical.DecodeOptions{MaxBytes: 1024})
	if err == nil {
		t.Errorf("size limit: %v", v)
	}
}

func TestDecodeTrailingWsOK(t *testing.T) {
	v, err := canonical.Decode([]byte(` { "x" : [ 1, 2 ] }   `), canonical.DecodeOptions{})
	if err != nil {
		t.Errorf("whitespace ok: %v", err.Error())
	}
	_ = v
}

func TestEscapeRoundTrip(t *testing.T) {
	s := "quote\" back\\ nl\n tab\tend \u00e9\u00e9"
	esc := canonical.Escape(s)
	v, err := canonical.Decode([]byte(esc), canonical.DecodeOptions{})
	if err != nil {
		t.Errorf("escape decode: %v", err.Error())
		return
	}
	if v.AsString() != s {
		t.Errorf("roundtrip: %q vs %q", v.AsString(), s)
	}
}

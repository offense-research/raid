package cli

import "testing"

func TestParseReceiptJSONStandalone(t *testing.T) {
	doc := `{"claims":{"request_hash":"sha256:ab","effect":"allow"},"key_id":"key_1","signature":"00ff","claims_bytes":"0102"}`
	cb, sig, kid, rh, errMsg := parseReceiptJSON(doc)
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	if string(cb) != "\x01\x02" {
		t.Errorf("claims_bytes: got %x", cb)
	}
	if string(sig) != "\x00\xff" {
		t.Errorf("signature: got %x", sig)
	}
	if kid != "key_1" {
		t.Errorf("key_id: got %q", kid)
	}
	if rh != "sha256:ab" {
		t.Errorf("request_hash: got %q", rh)
	}
}

func TestParseReceiptJSONWrapped(t *testing.T) {
	doc := `{"approval":{"id":"apr_1"},"receipt":{"claims":{"request_hash":"sha256:cd","effect":"allow"},"key_id":"k","signature":"aa","claims_bytes":"bb"}}`
	_, _, kid, rh, errMsg := parseReceiptJSON(doc)
	if errMsg != "" {
		t.Fatalf("unexpected error: %s", errMsg)
	}
	if kid != "k" || rh != "sha256:cd" {
		t.Errorf("kid=%q rh=%q", kid, rh)
	}
}

func TestParseReceiptJSONErrors(t *testing.T) {
	if _, _, _, _, e := parseReceiptJSON("not json"); e == "" {
		t.Error("expected error for non-json input")
	}
	if _, _, _, _, e := parseReceiptJSON(`{"key_id":"k"}`); e == "" {
		t.Error("expected error for missing signature/claims_bytes")
	}
	if _, _, _, _, e := parseReceiptJSON(`{"key_id":"k","signature":"zz","claims_bytes":"yy"}`); e == "" {
		t.Error("expected error for non-hex signature/claims_bytes")
	}
}

func TestParseKeysJSON(t *testing.T) {
	pub, kid := parseKeysJSON(`{"key_id":"k1","public_key":"0a0b"}`)
	if kid != "k1" || len(pub) != 2 {
		t.Errorf("kid=%q pub=%x", kid, pub)
	}
}

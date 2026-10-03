// Receipt verification: independently check a signed receipt against the
// issuer's public key and (optionally) the request it claims to authorize.
package cli

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/signing"
	"offense.dev/raid/pkg/raidclient"
)

func cmdReceipt(args []string) int {
	if len(args) < 1 {
		log.Printf("raid: receipt requires a subcommand (get|verify)")
		return 2
	}
	switch args[0] {
	case "get", "status":
		return receiptGet(args[1:])
	case "verify":
		return receiptVerify(args[1:])
	}
	log.Printf("raid: unknown receipt subcommand %q", args[0])
	return 2
}

func receiptGet(args []string) int {
	if len(args) != 1 {
		log.Printf("raid: receipt get <id>")
		return 2
	}
	client := raidclient.NewClient(socketPath())
	resp, err := client.Get("/v1/receipts/"+args[0], "")
	resp = checkErr(resp, err)
	fmt.Println(resp.BodyString())
	if resp.Status >= 400 {
		return 1
	}
	return 0
}

// receiptVerify checks a receipt's signature and binding. It accepts either a
// receipt id (fetched from the running daemon) or a `--receipt <file>` (the
// receipt JSON from an approve response, or a standalone receipt).
func receiptVerify(args []string) int {
	var id, file, requestFile, pubHex string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--receipt":
			if i+1 < len(args) {
				file = args[i+1]
				i++
			}
		case "--request":
			if i+1 < len(args) {
				requestFile = args[i+1]
				i++
			}
		case "--pubkey":
			if i+1 < len(args) {
				pubHex = args[i+1]
				i++
			}
		default:
			if len(a) > 0 && a[0] != '-' && id == "" {
				id = a
			}
		}
	}
	if id == "" && file == "" {
		log.Printf("raid: receipt verify <id> | --receipt <file> [--request <request.json>] [--pubkey <hex>]")
		return 2
	}

	var doc string
	var status string
	if file != "" {
		data, rerr := os.ReadFile(file)
		if rerr != nil {
			log.Printf("raid: %v", rerr)
			return 1
		}
		doc = string(data)
	} else {
		client := raidclient.NewClient(socketPath())
		resp, err := client.Get("/v1/receipts/"+id, "")
		resp = checkErr(resp, err)
		if resp.Status >= 400 {
			fmt.Println(resp.BodyString())
			return 1
		}
		doc = resp.BodyString()
		status = jsonStr(resp.Body, "status")
	}

	claimsBytes, signature, keyID, requestHash, perr := parseReceiptJSON(doc)
	if perr != "" {
		log.Printf("raid: %s", perr)
		return 1
	}

	pub := []byte(nil)
	if pubHex != "" {
		pub, _ = hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(pubHex, "0x"), "ed25519:"))
	} else {
		client := raidclient.NewClient(socketPath())
		resp, err := client.Get("/v1/keys", "")
		if err != nil {
			log.Printf("raid: cannot fetch issuer key (%v); pass --pubkey for offline verification", err)
			return 1
		}
		var kid string
		pub, kid = parseKeysJSON(resp.BodyString())
		if keyID == "" {
			keyID = kid
		}
	}
	if len(pub) == 0 {
		log.Printf("raid: no issuer public key available")
		return 1
	}

	rec := &signing.SignedReceipt{ClaimsBytes: claimsBytes, Signature: signature, KeyID: keyID}
	valid := signing.VerifyReceipt(rec, keyID, pub)

	fmt.Printf("key_id:    %s\n", keyID)
	fmt.Printf("signature: %v\n", valid)
	if status != "" {
		fmt.Printf("status:    %s\n", status)
	}
	fmt.Printf("request:   %s\n", requestHash)

	ok := valid
	if requestFile != "" {
		reqData, rerr := os.ReadFile(requestFile)
		if rerr != nil {
			log.Printf("raid: %v", rerr)
			return 1
		}
		req, derr := canonical.DecodeRequest(reqData)
		if derr != nil {
			log.Printf("raid: invalid request: %s", derr.Message())
			return 1
		}
		want := canonical.RequestHashString(canonical.HashRequest(req))
		match := want == requestHash
		fmt.Printf("binding:   request hash matches: %v\n", match)
		ok = ok && match
	}
	if !ok {
		return 1
	}
	return 0
}

// parseReceiptJSON extracts the signed material from a receipt document, which
// may be a standalone receipt or an approve response wrapping one.
func parseReceiptJSON(doc string) (claimsBytes, signature []byte, keyID, requestHash, errMsg string) {
	v, perr := canonical.Decode([]byte(doc), canonical.DecodeOptions{MaxBytes: 2 * 1024 * 1024})
	if perr != nil || v.Kind() != canonical.VObject {
		return nil, nil, "", "", "receipt is not a JSON object"
	}
	m := v.AsMap()
	if r, ok := m["receipt"]; ok && r.Kind() == canonical.VObject {
		m = r.AsMap()
	}
	keyID = mapStr(m, "key_id")
	cbHex := mapStr(m, "claims_bytes")
	sigHex := mapStr(m, "signature")
	if cbHex == "" || sigHex == "" {
		return nil, nil, "", "", "receipt missing signature or claims_bytes"
	}
	claimsBytes, _ = hex.DecodeString(cbHex)
	signature, _ = hex.DecodeString(sigHex)
	if len(claimsBytes) == 0 || len(signature) == 0 {
		return nil, nil, "", "", "receipt signature or claims_bytes is not valid hex"
	}
	if c, ok := m["claims"]; ok && c.Kind() == canonical.VObject {
		requestHash = mapStr(c.AsMap(), "request_hash")
	}
	return claimsBytes, signature, keyID, requestHash, ""
}

func parseKeysJSON(doc string) (pub []byte, keyID string) {
	v, err := canonical.Decode([]byte(doc), canonical.DecodeOptions{MaxBytes: 65536})
	if err != nil || v.Kind() != canonical.VObject {
		return nil, ""
	}
	m := v.AsMap()
	pub, _ = hex.DecodeString(mapStr(m, "public_key"))
	return pub, mapStr(m, "key_id")
}

func mapStr(m map[string]canonical.Value, key string) string {
	if v, ok := m[key]; ok && v.Kind() == canonical.VString {
		return v.AsString()
	}
	return ""
}

func jsonStr(body []byte, key string) string {
	v, err := canonical.Decode(body, canonical.DecodeOptions{MaxBytes: 65536})
	if err != nil || v.Kind() != canonical.VObject {
		return ""
	}
	return mapStr(v.AsMap(), key)
}

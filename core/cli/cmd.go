// Decision and approval CLI commands (noninteractive).
package cli

import (
	"fmt"
	"log"
	"os"

	"offense.dev/raid/core/canonical"
	"offense.dev/raid/core/tui"
	"offense.dev/raid/pkg/raidclient"
)

func cmdDecision(args []string) int {
	if len(args) < 1 {
		log.Printf("raid: decision requires a subcommand")
		return 2
	}
	switch args[0] {
	case "eval":
		return decisionEval(args[1:])
	case "get":
		return decisionGet(args[1:])
	case "wait":
		return decisionWait(args[1:])
	}
	log.Printf("raid: unknown decision subcommand %q", args[0])
	return 2
}

func decisionEval(args []string) int {
	var requestJSON string
	for i, a := range args {
		switch a {
		case "--request":
			if i + 1 < len(args) {
				requestJSON = args[i+1]
			}
		}
	}
	if requestJSON == "" {
		log.Printf("raid: decision eval --request <request.json>")
		return 2
	}
	data := readFileOrDie(requestJSON)
	client := raidclient.NewClient(socketPath())
	resp, err := client.Post("/v1/decisions", string(data), "", nil)
	resp = checkErr(resp, err)
	fmt.Println(resp.BodyString())
	if resp.Status >= 400 {
		return 1
	}
	return 0
}

func decisionGet(args []string) int {
	if len(args) != 1 {
		log.Printf("raid: decision get <id>")
		return 2
	}
	client := raidclient.NewClient(socketPath())
	resp, err := client.Get("/v1/decisions/"+args[0], "")
	resp = checkErr(resp, err)
	fmt.Println(resp.BodyString())
	return 0
}

func decisionWait(args []string) int {
	if len(args) < 1 {
		log.Printf("raid: decision wait <id> [--timeout Ns]")
		return 2
	}
	client := raidclient.NewClient(socketPath())
	resp, err := client.Get("/v1/decisions/"+args[0]+"/wait", "")
	resp = checkErr(resp, err)
	fmt.Println(resp.BodyString())
	return 0
}

func cmdApproval(args []string) int {
	if len(args) < 1 {
		log.Printf("raid: approval requires a subcommand")
		return 2
	}
	switch args[0] {
	case "list":
		client := raidclient.NewClient(socketPath())
		resp, err := client.Get("/v1/approvals", approverOf())
		resp = checkErr(resp, err)
		fmt.Println(resp.BodyString())
		return 0
	case "approve", "deny":
		if len(args) < 2 {
			log.Printf("raid: approval %v <id> --expected-version N", args[0])
			return 2
		}
		var version uint64
		for i, a := range args {
			if a == "--expected-version" && i + 1 < len(args) {
				v, ok := parseUint64(args[i+1])
				if ok {
					version = v
				}
			}
		}
		body := fmt.Sprintf(`{"expected_version":%d}`, version)
		client := raidclient.NewClient(socketPath())
		resp, err := client.Post("/v1/approvals/"+args[1]+"/"+args[0], body, approverOf(), nil)
		resp = checkErr(resp, err)
		fmt.Println(resp.BodyString())
		if resp.Status >= 400 {
			return 1
		}
		return 0
	case "cancel":
		if len(args) < 2 {
			log.Printf("raid: approval cancel <id>")
			return 2
		}
		sess := os.Getenv("RAID_SESSION")
		body := fmt.Sprintf(`{"session_id":%q}`, sess)
		client := raidclient.NewClient(socketPath())
		resp, err := client.Post("/v1/approvals/"+args[1]+"/cancel", body, "", nil)
		resp = checkErr(resp, err)
		fmt.Println(resp.BodyString())
		return 0
	}
	log.Printf("raid: unknown approval subcommand %q", args[0])
	return 2
}

func cmdDoctor(args []string) int {
	_ = args
	client := raidclient.NewClient(socketPath())
	resp, err := client.Get("/v1/policies/active", "")
	if err != nil {
		fmt.Println("raidd:   not reachable (" + err.Error() + ")")
		return 1
	}
	fmt.Println("raidd:   reachable")
	fmt.Println("policy:  " + resp.BodyString())
	return 0
}

// cmdLog prints the merged activity journal (decisions, approvals, audit).
func cmdLog(args []string) int {
	limit := "50"
	asJSON := false
	for i, a := range args {
		switch a {
		case "--limit", "-n":
			if i+1 < len(args) {
				limit = args[i+1]
			}
		case "--json":
			asJSON = true
		}
	}
	client := raidclient.NewClient(socketPath())
	resp, err := client.Get("/v1/journal?limit="+limit, "")
	resp = checkErr(resp, err)
	if asJSON {
		fmt.Println(resp.BodyString())
		return 0
	}
	v, perr := canonical.Decode(resp.Body, canonical.DecodeOptions{MaxBytes: 4 * 1024 * 1024})
	if perr != nil || v.Kind() != canonical.VObject {
		fmt.Println(resp.BodyString())
		return 0
	}
	entries, ok := v.AsMap()["entries"]
	if !ok || entries.Kind() != canonical.VList {
		fmt.Println("(no journal entries)")
		return 0
	}
	items := entries.AsList()
	if len(items) == 0 {
		fmt.Println("(no journal entries)")
		return 0
	}
	for _, it := range items {
		if it.Kind() != canonical.VObject {
			continue
		}
		m := it.AsMap()
		fmt.Printf("%-20s %-9s %-22s %s\n",
			atStr(m["at"]), kindStr(m["kind"]), kindStr(m["id"]), kindStr(m["detail"]))
	}
	return 0
}

func atStr(v canonical.Value) string {
	if v.Kind() == canonical.VString {
		s := v.AsString()
		if len(s) > 19 {
			return s[:19]
		}
		return s
	}
	return ""
}

func kindStr(v canonical.Value) string {
	if v.Kind() == canonical.VString {
		return v.AsString()
	}
	return ""
}

// cmdGrants lists active scoped grants.
func cmdGrants(args []string) int {
	_ = args
	client := raidclient.NewClient(socketPath())
	resp, err := client.Get("/v1/grants", "")
	resp = checkErr(resp, err)
	fmt.Println(resp.BodyString())
	return 0
}

func cmdApprove(args []string) int {
	_ = args
	return tui.Run()
}

func parseUint64(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	n := uint64(0)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n * 10 + uint64(c - '0')
	}
	return n, true
}
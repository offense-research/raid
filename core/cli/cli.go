// Raid CLI: operator commands and client wiring.
package cli

import (
	"fmt"
	"log"
	"os"

	"offense.dev/raid/core/util"
	"offense.dev/raid/pkg/raidclient"
)

// Dispatch handles `raid <args>`. Returns the process exit code.
func Dispatch(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 2
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "policy":
		return cmdPolicy(rest)
	case "decision":
		return cmdDecision(rest)
	case "approval":
		return cmdApproval(rest)
	case "grants":
		return cmdGrants(rest)
	case "log":
		return cmdLog(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "approve":
		return cmdApprove(rest)
	case "help", "-h", "--help":
		printUsage()
		return 0
	case "version", "--version":
		fmt.Println("raid 0.1.0-draft")
		return 0
	}
	log.Printf("raid: unknown command %q", cmd)
	printUsage()
	return 2
}

func printUsage() {
	fmt.Println(`usage: raid <command> [args]

commands:
  policy validate|test|diff|activate|init <file>...
  policy init --preset <name> [file]           # solo-dev-safe|review-only|ci-agent
  policy presets                               # list onboarding presets
  policy from-language --statement <nl perms> [--key <openrouter>] ...
  policy from-language --interactive            # Charm TUI authoring
  decision eval --request <request.json>
  approval list|approve|deny|cancel
  grants            (list active scoped grants)
  log [--limit N]   (activity journal: decisions, approvals, audit)
  doctor
  approve           (interactive TUI; requires a TTY)
`)
}

// socketPath returns the configured socket.
func socketPath() string {
	return util.DefaultSocket()
}

func approverOf() string {
	return os.Getenv("RAID_APPROVER")
}

func readFileOrDie(path string) []byte {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("raid: %v", err)
	}
	return data
}

func checkErr(resp *raidclient.Response, err error) *raidclient.Response {
	if err != nil {
		log.Fatalf("raid: %v", err.Error())
	}
	return resp
}

const adminGroups = "admins"
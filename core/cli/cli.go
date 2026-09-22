// Raid CLI: operator commands and client wiring.
package cli

import (
	"fmt"
	"log"
	"os"

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
  decision eval --request <request.json>
  approval list|approve|deny|cancel
  doctor
  approve           (interactive TUI; requires a TTY)
`)
}

// socketPath returns the configured socket.
func socketPath() string {
	v := os.Getenv("RAID_SOCKET")
	if v == "" {
		return "/run/offense/raid/raid.sock"
	}
	return v
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
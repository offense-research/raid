// Raid entry point.
//
// Raid ships as a single binary. The same executable acts as `raidd` (the
// long-running policy and approval daemon) and `raid` (the operator CLI);
// dispatch is by argv[0] basename (a `raidd` symlink selects the daemon).
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"offense.dev/raid/core/cli"
	"offense.dev/raid/core/server"
	"offense.dev/raid/core/util"
)

func main() {
	argv0 := ""
	if len(os.Args) > 0 {
		argv0 = os.Args[0]
	}
	base := argv0
	if i := strings.LastIndexByte(argv0, '/'); i >= 0 {
		base = argv0[i + 1:]
	}
	if base == "raidd" || base == "raid-daemon" {
		code := runDaemon(os.Args[1:])
		os.Exit(code)
		return
	}
	code := cli.Dispatch(os.Args[1:])
	os.Exit(code)
}

// runDaemon parses raidd flags and boots the server.
func runDaemon(args []string) int {
	var cfg server.Config
	socketSet := false
	for i, a := range args {
		switch a {
		case "--socket":
			if i + 1 < len(args) {
				cfg.SocketPath = args[i+1]
				socketSet = true
			}
		case "--db", "-d":
			if i + 1 < len(args) {
				cfg.DBPath = args[i+1]
			}
		case "--policy", "-p":
			if i + 1 < len(args) {
				cfg.PolicyFile = args[i+1]
			}
		case "--policy-preset":
			if i + 1 < len(args) {
				cfg.PolicyPreset = args[i+1]
			}
		case "--key":
			if i + 1 < len(args) {
				cfg.KeySeedFile = args[i+1]
			}
		case "--tcp":
			if i + 1 < len(args) {
				cfg.TCPAddr = args[i+1]
			}
		case "--uid":
			if i + 1 < len(args) {
				if u, ok := num(args[i+1]); ok {
					cfg.AllowUIDs = append(cfg.AllowUIDs, u)
				}
			}
		case "--approver":
			if i + 1 < len(args) {
				seed := parseApprover(args[i+1])
				cfg.Approvers = append(cfg.Approvers, seed)
			}
		case "--solo":
			cfg.Solo = true
		case "--forbid-self-approval":
			cfg.ForbidSelfApproval = true
		case "--help", "-h":
			printDaemonUsage()
			return 0
		}
	}
	if cfg.Solo {
		// Unprivileged single-user defaults under the XDG state dir; the
		// local user is auto-seeded as their own approver at boot.
		if !socketSet {
			cfg.SocketPath = util.StateFile("raid.sock")
		}
		if cfg.DBPath == "" {
			cfg.DBPath = util.DefaultDB()
		}
		if cfg.KeySeedFile == "" {
			cfg.KeySeedFile = util.DefaultKey()
		}
		if cfg.PolicyFile == "" && cfg.PolicyPreset == "" {
			cfg.PolicyPreset = "solo-dev-safe"
		}
	} else {
		if !socketSet {
			cfg.SocketPath = util.SystemSocketDefault
		}
		if cfg.DBPath == "" {
			cfg.DBPath = os.Getenv("RAID_DB")
		}
		if cfg.DBPath == "" {
			cfg.DBPath = "/var/lib/offense/raid/raid.db"
		}
		if cfg.KeySeedFile == "" {
			cfg.KeySeedFile = os.Getenv("RAID_KEY")
		}
		if cfg.KeySeedFile == "" {
			cfg.KeySeedFile = "/var/lib/offense/raid/ed25519.seed"
		}
	}
	if len(cfg.Approvers) == 0 {
		// default local approver set from the environment
		if v := os.Getenv("RAID_APPROVERS"); v != "" {
			for _, entry := range strings.Split(v, ";") {
				cfg.Approvers = append(cfg.Approvers, parseApprover(entry))
			}
		}
	}
	// ensure the socket directory exists
	if cfg.SocketPath != "" {
		dir := dirnameOf(cfg.SocketPath)
		if dir != "." && dir != "/" {
			_ = os.Mkdir(dir, 0o755)
		}
	}
	if err := server.Start(cfg); err != nil {
		log.Fatalf("raidd: %v", err)
	}
	return 0
}

// parseApprover parses "subject:group1,group2[:enabled]".
func parseApprover(entry string) server.ApproverSeed {
	parts := strings.Split(entry, ":")
	var seed server.ApproverSeed
	if len(parts) >= 1 {
		seed.SubjectID = parts[0]
	}
	if len(parts) >= 2 {
		seed.Groups = strings.Split(parts[1], ",")
	}
	seed.Enabled = true
	if len(parts) >= 3 && parts[2] == "0" {
		seed.Enabled = false
	}
	return seed
}

func num(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n := int64(0)
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n * 10 + int64(c - '0')
	}
	return n, true
}

func dirnameOf(path string) string {
	i := strings.LastIndexByte(path, '/')
	if i < 0 {
		return "."
	}
	if i == 0 {
		return "/"
	}
	return path[:i]
}

func printDaemonUsage() {
	fmt.Println(`raidd [flags]

  --socket <path>      unix socket path (default /run/offense/raid/raid.sock)
  --db <path>          sqlite database path
  --policy <file>      policy bundle to activate at boot
  --policy-preset <n>  activate an embedded preset (solo-dev-safe|review-only|ci-agent)
  --key <path>         ed25519 seed file (generated when absent)
  --tcp <addr>         optional tcp listener (remote mode)
  --uid <n>            allow unix socket peer uid (repeatable)
  --approver <subject:groups>  seed an approver (repeatable)
  --solo               unprivileged single-user mode (XDG state dir, self-approval)
  --forbid-self-approval       reject approvers submitting their own request
`)
}

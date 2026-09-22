// Daemon bootstrap: wires store, engine, approvals, and the API server.
package server

import (
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"offense.dev/raid/core/api"
	"offense.dev/raid/core/approval"
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

// Config is the daemon configuration (flags / config file).
type Config struct {
	DBPath      string
	SocketPath  string
	TCPAddr     string // empty => unix only
	PolicyFile  string // activated at boot when set
	AllowUIDs   []int64
	Approvers   []ApproverSeed
	KeySeedFile string
	ForbidSelfApproval bool
	LogVerbose  bool
}

// ApproverSeed is an admin-seeded approver entry.
type ApproverSeed struct {
	SubjectID string
	Groups    []string
	Enabled   bool
}

// Daemon is the running server.
type Daemon struct {
	Cfg    Config
	Srv    *api.Server
	Store  *store.Store
	Engine *decision.Engine
	svc    *approval.Service
	Run    bool
}

// Start boots the daemon and blocks serving requests.
func Start(cfg Config) error {
	d, err := Boot(cfg)
	if err != nil {
		return err
	}
	return d.Serve()
}

// Boot initializes all subsystems but does not serve.
func Boot(cfg Config) (*Daemon, error) {
	st, err := store.Open(store.Options{Path: cfg.DBPath, AuditMode: store.BalancedAudit})
	if err != nil {
		return nil, err
	}
	engine := decision.NewEngine()
	key, kerr := loadKey(cfg.KeySeedFile)
	if kerr != nil {
		return nil, kerr
	}
	hub := stream.NewHub()
	apprStore := authn.NewApproverStore(st)
	for _, seed := range cfg.Approvers {
		for _, g := range seed.Groups {
			if err := apprStore.Upsert(seed.SubjectID, g, seed.Enabled); err != nil {
				return nil, err
			}
		}
	}
	svc := approval.NewService(st, key, hub, cfg.ForbidSelfApproval)
	var evaluator jev.SemanticEvaluator
	if k := os.Getenv("TYPESAFE_API_KEY"); k != "" {
		evaluator = jev.NewHttpEvaluator("", k, "", 650 * int64(time.Millisecond))
	}
	server := api.NewServer(api.Config{
		Engine: engine, Approvals: svc, Store: st, Hub: hub, Key: key,
		Approvers: apprStore, AllowUIDs: cfg.AllowUIDs, Evaluator: evaluator,
	})
	d := &Daemon{Cfg: cfg, Srv: server, Store: st, Engine: engine, svc: svc, Run: true}
	if cfg.PolicyFile != "" {
		if lerr := d.ActivateAttempt(cfg.PolicyFile); lerr != nil {
			return nil, errors.New("raid: policy activation failed at boot: " + lerr.Error())
		}
	}
	return d, nil
}

// Activate compiles and activates a policy file, recording the activation.
func (d *Daemon) Activate(path string) bool {
	return d.ActivateAttempt(path) == nil
}

func (d *Daemon) ActivateAttempt(path string) error {
	schema, lerr := policy.LoadBundleFile(path)
	if lerr != nil {
		return lerr
	}
	dir := dirnameOf(path)
	loader := func(input string) (*canonical.ActionRequest, error) {
		full := dir + "/" + input
		data, rerr := os.ReadFile(full)
		if rerr != nil {
			return nil, rerr
		}
		return canonical.DecodeRequest(data)
	}
	bundle, cerr := policy.CompileBundle(schema, policy.CompileOptions{RequestLoader: loader})
	if cerr != nil {
		return cerr
	}
	now := time.Now().UTC()
	if _, err := d.Store.Exec(`INSERT INTO policy_bundles (id, name, revision, bundle_hash, active, activated_at_ns)
		VALUES (?, ?, ?, ?, 1, ?) ON CONFLICT(id) DO UPDATE SET active = 1, bundle_hash = excluded.bundle_hash`,
		bundle.ID(), bundle.Name(), bundle.Revision(), bundle.Hash(), now.UnixNano()); err != nil {
		return err
	}
	if _, err := d.Store.Exec(`UPDATE policy_bundles SET active = 0 WHERE id != ?`, bundle.ID()); err != nil {
		return err
	}
	if _, err := d.Store.Exec(`INSERT INTO policy_activations (id, bundle_id, actor, activated_at_ns)
		VALUES (?, ?, ?, ?)`, util.NewID("act"), bundle.ID(), "admin:" + userName(), now.UnixNano()); err != nil {
		return err
	}
	d.Engine.Activate(bundle)
	return nil
}

func userName() string {
	v := os.Getenv("RAID_ADMIN")
	if v != "" {
		return v
	}
	return "local-admin"
}

// Serve runs the sweep ticker and serves the API; returns on shutdown.
func (d *Daemon) Serve() error {
	go d.sweepLoop()
	if d.Cfg.SocketPath != "" {
		go func() {
			if err := d.Srv.ServeUnix(d.Cfg.SocketPath); err != nil {
				log.Printf("raid: unix server error: %v", err)
				os.Exit(1)
			}
		}()
	}
	if d.Cfg.TCPAddr != "" {
		go func() {
			if err := d.Srv.ServeTCP(d.Cfg.TCPAddr); err != nil {
				log.Printf("raid: tcp server error: %v", err)
				os.Exit(1)
			}
		}()
	}
	if d.Cfg.SocketPath == "" && d.Cfg.TCPAddr == "" {
		return errors.New("raid: no listener configured")
	}
	for {
		time.Sleep(1 << 30 * time.Nanosecond)
	}
	return nil
}

func (d *Daemon) sweepLoop() () {
	for {
		time.Sleep(5 * time.Second)
		_, _ = d.svc.SweepExpired()
	}
}

// loadKey loads the Ed25519 seed file or generates and persists one.
func loadKey(path string) (*signing.KeyPair, error) {
	data, err := os.ReadFile(path)
	if err == nil && len(data) >= 32 {
		k, kerr := signing.FromSeed(data[:32])
		if kerr != nil {
			return nil, kerr
		}
		return k, nil
	}
	k, kerr := signing.GenerateKey()
	if kerr != nil {
		return nil, kerr
	}
	if werr := os.WriteFile(path, k.Seed(), 0o600); werr != nil {
		log.Printf("raid: warning: could not persist signing key: %v", werr)
	}
	return k, nil
}

// dirnameOf returns the directory portion of a path.
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
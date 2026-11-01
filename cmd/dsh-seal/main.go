// Command dsh-seal is the application layer encrypted channel in front of
// dsh-proxy. See README.md and docs/PROTOCOL.md.
//
// Usage:
//
//	dsh-seal [-config FILE]           run the service
//	dsh-seal -config FILE fingerprint print the identity fingerprint
//	dsh-seal -config FILE rotate-identity
//	dsh-seal -config FILE check       validate the config and exit
//	dsh-seal -config FILE bundle-json print the public key bundle
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dsh-seal/internal/keystore"
	"dsh-seal/internal/server"
)

func main() {
	cfgPath := flag.String("config", os.Getenv("DSH_SEAL_CONFIG"), "config file (key=value)")
	flag.Parse()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := server.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	cmd := flag.Arg(0)
	if cmd == "check" {
		fmt.Printf("config ok: listen=%s upstream=%s mode=%s identities=%v\n", cfg.Listen, cfg.Upstream, cfg.Mode, cfg.Identities)
		return
	}
	keys, err := keystore.Open(cfg.StateDir, cfg.KXRotate)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch cmd {
	case "fingerprint":
		b := keys.Bundle()
		fmt.Printf("identity %s\nkx %s expires %s\n", b.FP, b.KX.KID, time.Unix(int64(b.KX.Exp), 0).UTC().Format(time.RFC3339))
		return
	case "bundle-json":
		j, _ := json.Marshal(keys.Bundle())
		fmt.Println(string(j))
		return
	case "rotate-identity":
		if err := keys.RotateIdentity(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("identity rotated, new fingerprint", keys.Fingerprint(), "(restart or reload dsh-seal)")
		return
	case "":
	default:
		fmt.Fprintln(os.Stderr, "unknown command", cmd)
		os.Exit(2)
	}

	s := server.New(cfg, keys, log)
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen failed", "code", "SEAL_LISTEN", "err", err)
		os.Exit(1)
	}
	hs := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	log.Info("dsh-seal listening", "listen", cfg.Listen, "upstream", cfg.Upstream, "mode", cfg.Mode, "fingerprint", keys.Fingerprint(), "version", server.Version, "egress", cfg.Egress)

	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			s.GC()
			s.Egress.FlushStats(log)
			if changed, err := keys.Maintain(); err != nil {
				log.Error("key maintenance failed", "code", "SEAL_KEYS_WRITE", "err", err)
			} else if changed {
				s.Reload(*s.Cfg())
				log.Info("key exchange key rotated", "kid", keys.Bundle().KX.KID)
			}
		}
	}()
	go func() {
		for v := range sig {
			if v == syscall.SIGHUP {
				nc, err := server.Load(*cfgPath)
				if err != nil {
					log.Error("reload failed, keeping the old config", "code", "SEAL_CONFIG", "err", err)
					continue
				}
				s.Reload(nc)
				log.Info("config reloaded", "mode", nc.Mode, "identities", nc.Identities, "egress", nc.Egress)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			hs.Shutdown(ctx)
			cancel()
			return
		}
	}()
	if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve failed", "err", err)
		os.Exit(1)
	}
}

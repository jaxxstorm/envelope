package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jaxxstorm/envelope/internal/controller/attestation"
	"github.com/jaxxstorm/envelope/internal/controller/strictjson"
)

var version = "dev"
var revision = "unknown"
var buildDate = "unknown"
var sourceModified = "true"

func immutableRead(path string, maximum int64, secret bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, attestation.ErrRejected
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return nil, attestation.ErrRejected
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return nil, attestation.ErrRejected
		}
		if directory == "/" {
			break
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 || info.Size() > maximum {
		return nil, attestation.ErrRejected
	}
	if secret && info.Mode().Perm() != 0400 {
		return nil, attestation.ErrRejected
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, attestation.ErrRejected
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, attestation.ErrRejected
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, attestation.ErrRejected
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(payload)) > maximum {
		return nil, attestation.ErrRejected
	}
	return payload, nil
}

func run(ctx context.Context, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "identity":
			return configurationIdentity(args[1:])
		case "provision-key":
			return provisionKey(ctx, args[1:])
		case "enroll":
			return enroll(ctx, args[1:])
		}
	}
	if len(args) == 1 && args[0] == "version" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"component": "envelope-router-attestor", "version": version, "revision": revision, "build_date": buildDate, "source_modified": sourceModified})
	}
	flags := flag.NewFlagSet("envelope-router-attestor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", enrollmentDirectory+"/config.json", "immutable enrollment and collector configuration")
	keyPath := flags.String("signing-key", enrollmentDirectory+"/signing-key", "root-owned mode-0400 Ed25519 seed (hex)")
	listen := flags.String("listen", "127.0.0.1:9443", "private attestation address")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return attestation.ErrRejected
	}
	payload, err := immutableRead(*path, 4*1024*1024, false)
	if err != nil || strictjson.Validate(payload, 4*1024*1024) != nil {
		return attestation.ErrRejected
	}
	var configuration attestation.CollectorConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&configuration) != nil {
		return attestation.ErrRejected
	}
	authority, owner, err := configuration.Authority()
	if err != nil {
		return err
	}
	seedHex, err := immutableRead(*keyPath, 64, true)
	if err != nil || len(seedHex) != 64 {
		return attestation.ErrRejected
	}
	seed, err := hex.DecodeString(string(seedHex))
	if err != nil || len(seed) != ed25519.SeedSize {
		return attestation.ErrRejected
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	clear(seedHex)
	public, err := hex.DecodeString(configuration.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || subtle.ConstantTimeCompare(public, key.Public().(ed25519.PublicKey)) != 1 {
		return attestation.ErrRejected
	}
	collector, err := attestation.NewNativeCollector(configuration)
	if err != nil {
		return err
	}
	policy := configuration.Topology.Policy
	configurationHash, err := configuration.Hash()
	if err != nil {
		return err
	}
	handler, err := attestation.NewHandler(authority, owner, key, collector, policy.ObservationFreshness.Duration(), policy.APITimeout.Duration(), configurationHash)
	if err != nil {
		return err
	}
	tlsConfiguration, err := attestation.ServerTLS(key)
	clear(key)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: handler, TLSConfig: tlsConfiguration, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: policy.APITimeout.Duration() + time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err = server.ListenAndServeTLS("", "")
	if err == http.ErrServerClosed {
		return nil
	}
	return attestation.ErrRejected
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "router attestor failed closed")
		os.Exit(1)
	}
}

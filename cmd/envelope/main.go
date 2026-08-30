package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jaxxstorm/envelope/internal/app"
	"github.com/jaxxstorm/envelope/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version        = "dev"
	revision       = "unknown"
	buildDate      = "unknown"
	sourceModified = "unknown"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(versionString())
		return
	}
	cfg, err := config.ParseTarget(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	log := newLogger(cfg.LogLevel)
	defer log.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Restore default signal behavior after first interrupt so a second Ctrl+C
		// force-terminates if graceful shutdown is stuck.
		stop()
	}()

	if err := app.Run(ctx, cfg, log); err != nil {
		log.Error("envelope exited with error", zap.Error(err))
		os.Exit(1)
	}
}

func versionString() string {
	return fmt.Sprintf("envelope %s revision=%s modified=%s built=%s go=%s", version, revision, sourceModified, buildDate, runtime.Version())
}

func newLogger(level string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(parseLevel(level))
	logger, err := cfg.Build()
	if err != nil {
		return zap.NewNop()
	}
	return logger
}

func parseLevel(level string) zapcore.Level {
	switch level {
	case "debug":
		return zapcore.DebugLevel
	case "warn":
		return zapcore.WarnLevel
	case "error":
		return zapcore.ErrorLevel
	default:
		return zapcore.InfoLevel
	}
}

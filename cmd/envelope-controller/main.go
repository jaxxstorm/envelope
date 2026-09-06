package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	controllerapp "github.com/jaxxstorm/envelope/internal/controller/app"
	controllerconfig "github.com/jaxxstorm/envelope/internal/controller/config"
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
	runtimeConfig, err := controllerconfig.ParseController(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	logger := newLogger(runtimeConfig.LogLevel)
	defer logger.Sync()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		// Match the packet target: a second signal restores forceful process
		// termination if graceful shutdown cannot complete.
		stop()
	}()

	if err := controllerapp.Run(ctx, runtimeConfig, logger); err != nil {
		logger.Error("envelope-controller exited with error",
			zap.String("reason", controllerapp.SafeErrorReason(err)),
		)
		os.Exit(1)
	}
}

func versionString() string {
	return fmt.Sprintf("envelope-controller %s revision=%s modified=%s built=%s go=%s", version, revision, sourceModified, buildDate, runtime.Version())
}

func newLogger(level string) *zap.Logger {
	configuration := zap.NewProductionConfig()
	configuration.Level = zap.NewAtomicLevelAt(parseLevel(level))
	logger, err := configuration.Build()
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

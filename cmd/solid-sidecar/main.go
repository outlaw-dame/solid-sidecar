package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/outlaw-dame/solid-sidecar/internal/config"
	"github.com/outlaw-dame/solid-sidecar/internal/gateway"
	"github.com/outlaw-dame/solid-sidecar/internal/observability"
)

func main() {
	os.Exit(run())
}

func run() int {
	var configPath string
	var listenAddress string
	var backendURL string
	flag.StringVar(&configPath, "config", os.Getenv("SOLID_SIDECAR_CONFIG"), "Path to sidecar configuration file")
	flag.StringVar(&listenAddress, "listen", "", "Override server listen address, e.g. :8443")
	flag.StringVar(&backendURL, "backend-url", "", "Override Community Solid Server backend URL")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		return 2
	}
	if listenAddress != "" {
		cfg.Server.Address = listenAddress
	}
	if backendURL != "" {
		cfg.Backend.URL = backendURL
	}
	if err := config.Validate(cfg); err != nil {
		slog.Error("invalid configuration", "error", err)
		return 2
	}

	logger := observability.NewLogger(cfg.Log.Level)
	server, err := gateway.New(cfg, logger)
	if err != nil {
		logger.Error("failed to create gateway", "error", err)
		return 2
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()

	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-signalCh:
		logger.Info("received shutdown signal", "signal", sig.String())
		if err := server.Shutdown(context.Background()); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
			return 1
		}
		return 0
	case err := <-errCh:
		if err != nil {
			logger.Error("server stopped", "error", err)
			return 1
		}
		return 0
	}
}

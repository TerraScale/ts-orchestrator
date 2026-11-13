package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type configuration struct{ Work string }

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		return err
	}
	var cfg configuration
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	switch os.Args[1] {
	case "node":
		return nodeMain(ctx, cfg)
	case "authority":
		return authorityMain(ctx, cfg)
	case "journey":
		bounded, stop := context.WithTimeout(ctx, 90*time.Second)
		defer stop()
		started := time.Now()
		err := journey(bounded, cfg)
		fmt.Printf("certificate journey: %s\n", time.Since(started).Round(time.Millisecond))
		return err
	default:
		return fmt.Errorf("unknown certificate journey process")
	}
}

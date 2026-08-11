// Command gopr is a TCP/UDP port forwarder and proxy. See SKILL.md for the
// full command-line specification.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gopr/internal/config"
	"gopr/internal/proxy"
	"gopr/internal/relay"
)

// version is gopr's release version, reported by -version. It is embedded
// at build time via -ldflags "-X main.version=<value>" (see build.gradle's
// build/goBuildAll tasks, which pass gradle.properties' VERSION_NAME); a
// plain "go build" leaves it at "dev".
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gopr:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfgs, err := config.ParseAll(args)
	if err != nil {
		return err
	}

	if len(cfgs) == 1 {
		switch cfgs[0].Mode {
		case config.ModeHelp:
			fmt.Println(config.Usage)
			return nil
		case config.ModeVersion:
			fmt.Println("gopr version " + version)
			return nil
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Every cfgs entry is independently valid at this point (config.ParseAll
	// only ever returns them all-or-nothing), so run them all concurrently
	// under one shared, cancellable context -- equivalent to launching one
	// gopr process per "--"-separated argument group.
	var wg sync.WaitGroup
	errCh := make(chan error, len(cfgs))
	for _, cfg := range cfgs {
		wg.Add(1)
		go func(cfg *config.Config) {
			defer wg.Done()
			if err := runOne(ctx, cfg); err != nil {
				errCh <- err
			}
		}(cfg)
	}
	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func runOne(ctx context.Context, cfg *config.Config) error {
	switch cfg.Mode {
	case config.ModeHTTPProxy:
		return proxy.RunHTTP(ctx, cfg)
	case config.ModeSOCKSProxy:
		return proxy.RunSOCKS(ctx, cfg)
	default:
		return relay.Run(ctx, cfg)
	}
}

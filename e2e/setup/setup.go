// Copyright 2022-2024 Sauce Labs Inc., all rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package setup

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/saucelabs/forwarder/utils/compose"
	"go.uber.org/multierr"
	"golang.org/x/sync/errgroup"
)

const TestServiceName = "test"

var CI bool

func init() {
	_, CI = os.LookupEnv("CI")
}

type Setup struct {
	Name    string
	Compose *compose.Compose
	Run     string
}

type Runner struct {
	Setups      []Setup
	SetupRegexp *regexp.Regexp
	Decorate    func(*Setup)
	Debug       bool
	Parallel    int

	td errgroup.Group
	mu sync.Mutex
}

func (r *Runner) Run(ctx context.Context) error {
	g, _ := errgroup.WithContext(ctx)
	if r.Parallel > 0 {
		g.SetLimit(r.Parallel)
	}
	if r.Debug {
		g.SetLimit(1)
	}

	setups := slices.Clone(r.Setups)
	if r.Parallel != 1 {
		rand.Shuffle(len(setups), func(i, j int) {
			setups[i], setups[j] = setups[j], setups[i]
		})
	}

	for i := range setups {
		s := &setups[i]

		if r.SetupRegexp != nil && !r.SetupRegexp.MatchString(s.Name) {
			continue
		}
		if r.Decorate != nil {
			r.Decorate(s)
		}
		g.Go(func() error {
			return r.runSetup(s)
		})
		if r.Debug {
			break
		}
	}

	// Don't wait for cleanup if running in CI.
	if CI {
		return g.Wait()
	}

	return multierr.Combine(g.Wait(), r.td.Wait())
}

func (r *Runner) runSetup(s *Setup) (runErr error) {
	start := time.Now()

	var stdout, stderr bytes.Buffer
	cmd, err := compose.NewCommand(s.Compose, &stdout, &stderr)
	if err != nil {
		return err
	}

	defer func() {
		if r.Debug {
			if err := copyComposeFile(cmd.File()); err != nil {
				fmt.Fprintf(os.Stderr, "failed to copy compose file: %v\n", err)
				os.Exit(1)
			}

			if err := cmd.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to close compose: %v\n", err)
				os.Exit(1)
			}

			fmt.Fprintf(os.Stdout, "To debug, run:\n\n COMPOSE_PROJECT_NAME=%s %s compose <command> ...\n\n", cmd.Runtime(), cmd.Project())
		} else {
			r.td.Go(func() error {
				if err := cmd.Down("-v"); err != nil {
					return fmt.Errorf("compose down: %w", err)
				}
				if err := cmd.Close(); err != nil {
					return fmt.Errorf("compose close: %w", err)
				}
				return nil
			})
		}
	}()

	defer func() {
		// Protect against concurrent writes to stdout/stderr.
		r.mu.Lock()
		defer r.mu.Unlock()

		if runErr == nil {
			fmt.Fprintf(os.Stdout, "=== setup %s PASS (duration: %s)\n", s.Name, time.Since(start))
			return
		}

		w := os.Stderr

		fmt.Fprintf(w, "=== setup %s FAIL (duration: %s)\n", s.Name, time.Since(start))

		if b, err := os.ReadFile(cmd.File()); err != nil {
			fmt.Fprintf(w, "failed to read compose file: %v\n", err)
		} else {
			fmt.Fprintf(w, "\n%s\n", b)
		}

		fmt.Fprintf(w, "\n")

		if err := cmd.Ps(); err != nil {
			fmt.Fprintf(w, "failed to ps: %v\n", err)
		}

		fmt.Fprintf(w, "\n")

		if err := cmd.Logs(); err != nil {
			fmt.Fprintf(w, "failed to get logs: %v\n", err)
		}

		stdout.WriteTo(w)
		stderr.WriteTo(w)
	}()

	// Bring up all services except the test service.
	args := []string{"-d", "--force-recreate", "--remove-orphans"}

	for name := range s.Compose.Services {
		if name == TestServiceName {
			continue
		}
		args = append(args, name)
	}

	if err := cmd.Up(args...); err != nil {
		return fmt.Errorf("compose up: %w", err)
	}

	// Wait for services to be ready.
	waitTimeout := 10 * time.Second
	if CI {
		waitTimeout = 60 * time.Second
	}
	if err := cmd.Wait(time.Second, waitTimeout); err != nil {
		return fmt.Errorf("wait for services: %w", err)
	}

	// Run the test service.
	return cmd.Up("--force-recreate", "--exit-code-from", TestServiceName, TestServiceName)
}

func copyComposeFile(input string) error {
	src, err := os.Open(input)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create("compose.yaml")
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	return dst.Close()
}

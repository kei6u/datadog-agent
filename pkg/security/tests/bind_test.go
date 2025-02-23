// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build functionaltests
// +build functionaltests

package tests

import (
	"fmt"
	"net"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"

	sprobe "github.com/DataDog/datadog-agent/pkg/security/probe"
	"github.com/DataDog/datadog-agent/pkg/security/secl/rules"
)

func TestBindEvent(t *testing.T) {
	ruleDefs := []*rules.RuleDefinition{
		{
			ID:         "test_bind_af_inet",
			Expression: `bind.addr.family == AF_INET && process.file.name == "syscall_tester"`,
		},
		{
			ID:         "test_bind_af_inet6",
			Expression: `bind.addr.family == AF_INET6 && process.file.name == "syscall_tester"`,
		},
		{
			ID:         "test_bind_af_unix",
			Expression: `bind.addr.family == AF_UNIX && process.file.name == "syscall_tester"`,
		},
	}

	test, err := newTestModule(t, nil, ruleDefs, testOpts{})
	if err != nil {
		t.Fatal(err)
	}
	defer test.Close()

	syscallTester, err := loadSyscallTester(t, test, "syscall_tester")
	if err != nil {
		t.Fatal(err)
	}

	test.Run(t, "bind-af-inet-any-success", func(t *testing.T, kind wrapperType, cmdFunc func(cmd string, args []string, envs []string) *exec.Cmd) {
		args := []string{"bind", "AF_INET", "any"}
		envs := []string{}

		test.WaitSignal(t, func() error {
			cmd := cmdFunc(syscallTester, args, envs)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %w", out, err)
			}

			return nil
		}, func(event *sprobe.Event, r *rules.Rule) {
			assert.Equal(t, "bind", event.GetType(), "wrong event type")
			assert.Equal(t, uint16(unix.AF_INET), event.Bind.AddrFamily, "wrong address family")
			assert.Equal(t, uint16(4242), event.Bind.Addr.Port, "wrong address port")
			assert.Equal(t, string("0.0.0.0/32"), event.Bind.Addr.IPNet.String(), "wrong address")
			assert.Equal(t, int64(0), event.Bind.Retval, "wrong retval")

			if !validateBindSchema(t, event) {
				t.Error(event.String())
			}
		})
	})

	test.Run(t, "bind-af-inet6-any-success", func(t *testing.T, kind wrapperType, cmdFunc func(cmd string, args []string, envs []string) *exec.Cmd) {
		args := []string{"bind", "AF_INET6", "any"}
		envs := []string{}

		test.WaitSignal(t, func() error {
			cmd := cmdFunc(syscallTester, args, envs)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %w", out, err)
			}

			return nil
		}, func(event *sprobe.Event, r *rules.Rule) {
			assert.Equal(t, "bind", event.GetType(), "wrong event type")
			assert.Equal(t, uint16(unix.AF_INET6), event.Bind.AddrFamily, "wrong address family")
			assert.Equal(t, uint16(4242), event.Bind.Addr.Port, "wrong address port")
			assert.Equal(t, string("::/128"), event.Bind.Addr.IPNet.String(), "wrong address")
			assert.Equal(t, int64(0), event.Bind.Retval, "wrong retval")

			if !validateBindSchema(t, event) {
				t.Error(event.String())
			}
		})
	})

	test.Run(t, "bind-af-unknown-unix", func(t *testing.T, kind wrapperType, cmdFunc func(cmd string, args []string, envs []string) *exec.Cmd) {
		args := []string{"bind", "AF_UNIX"}
		envs := []string{}

		test.WaitSignal(t, func() error {
			cmd := cmdFunc(syscallTester, args, envs)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("%s: %w", out, err)
			}

			return nil
		}, func(event *sprobe.Event, r *rules.Rule) {
			assert.Equal(t, "bind", event.GetType(), "wrong event type")
			assert.Equal(t, uint16(unix.AF_UNIX), event.Bind.AddrFamily, "wrong address family")
			assert.Equal(t, uint16(0), event.Bind.Addr.Port, "wrong address port")
			assert.Equal(t, net.IPNet{IP: net.IP(nil), Mask: net.IPMask(nil)},
				event.Bind.Addr.IPNet, "wrong address")
			assert.Equal(t, int64(0), event.Bind.Retval, "wrong retval")

			if !validateBindSchema(t, event) {
				t.Error(event.String())
			}
		})
	})
}

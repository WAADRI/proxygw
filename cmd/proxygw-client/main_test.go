package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"proxygw/internal/config"
	"proxygw/internal/nodeagent"
)

type fakeClientSession struct {
	run func(context.Context) error
}

func (f *fakeClientSession) Run(ctx context.Context) error { return f.run(ctx) }
func (f *fakeClientSession) Close() error                  { return nil }
func (f *fakeClientSession) Status() nodeagent.Status      { return nodeagent.Status{} }
func (f *fakeClientSession) ClientID() string              { return "fake-node" }
func (f *fakeClientSession) BootMessages() []string        { return nil }

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRunClientLoopReconnectsAfterServerShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	created := 0
	secondStarted := make(chan struct{})
	newClient := func() (clientSession, error) {
		mu.Lock()
		created++
		n := created
		mu.Unlock()
		if n == 1 {
			// Server asked for shutdown: Run returns nil without local cancel.
			return &fakeClientSession{run: func(context.Context) error { return nil }}, nil
		}
		return &fakeClientSession{run: func(ctx context.Context) error {
			close(secondStarted)
			<-ctx.Done()
			return nil
		}}, nil
	}

	done := make(chan int, 1)
	go func() {
		done <- runClientLoop(ctx, testLogger(), &config.ClientConfig{}, newClient, 10*time.Millisecond)
	}()

	select {
	case <-secondStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("客户端没有在服务端停机后重建 agent")
	}
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runClientLoop 退出码 = %d, want 0", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runClientLoop 未退出")
	}
	mu.Lock()
	defer mu.Unlock()
	if created != 2 {
		t.Fatalf("newClient 调用次数 = %d, want 2", created)
	}
}

func TestRunClientLoopStopsOnLocalSignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	newClient := func() (clientSession, error) {
		return &fakeClientSession{run: func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return nil
		}}, nil
	}
	done := make(chan int, 1)
	go func() {
		done <- runClientLoop(ctx, testLogger(), &config.ClientConfig{}, newClient, 10*time.Millisecond)
	}()
	<-started
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("本地停机退出码 = %d, want 0", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("本地停机后 runClientLoop 未退出")
	}
}

func TestRunClientLoopStopsOnFatalError(t *testing.T) {
	created := 0
	newClient := func() (clientSession, error) {
		created++
		return &fakeClientSession{run: func(context.Context) error {
			return errors.New("fatal: authentication failed")
		}}, nil
	}
	code := runClientLoop(context.Background(), testLogger(), &config.ClientConfig{}, newClient, 10*time.Millisecond)
	if code != 1 {
		t.Fatalf("致命错误退出码 = %d, want 1", code)
	}
	if created != 1 {
		t.Fatalf("致命错误后 newClient 调用次数 = %d, want 1", created)
	}
}

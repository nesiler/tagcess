package sync

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func newTestTrigger(t *testing.T, cfg TriggerConfig) *Trigger {
	t.Helper()
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	tr, err := NewTrigger(cfg)
	if err != nil {
		t.Fatalf("NewTrigger: %v", err)
	}
	return tr
}

func stopTrigger(t *testing.T, tr *Trigger) {
	t.Helper()
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

// AC1: signals that arrive within the debounce window become one reconcile.
func TestTrigger_Debounce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error {
			calls.Add(1)
			return nil
		}})
		tr.Start()
		defer stopTrigger(t, tr)

		tr.Signal()
		time.Sleep(time.Second)
		tr.Signal()
		time.Sleep(900 * time.Millisecond)
		tr.Signal()
		time.Sleep(DefaultDebounce)

		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("reconcile runs = %d, want 1 (a burst within %s must coalesce)", got, DefaultDebounce)
		}
	})
}

// AC2: a single signal starts a reconcile within 5 seconds.
func TestTrigger_Latency(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan time.Time, 1)
		tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error {
			started <- time.Now()
			return nil
		}})
		tr.Start()
		defer stopTrigger(t, tr)

		signalled := time.Now()
		tr.Signal()
		time.Sleep(DefaultDebounce)
		synctest.Wait()

		select {
		case at := <-started:
			if d := at.Sub(signalled); d > 5*time.Second {
				t.Fatalf("reconcile started after %s, want <= 5s", d)
			}
		default:
			t.Fatal("no reconcile started within the debounce window")
		}
	})
}

// AC3: the periodic reconcile fires every interval and uses a changed interval for the next period.
// A periodic tick goes through the shared debounce, so the run lands one debounce after the tick.
func TestTrigger_Periodic(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			mu   sync.Mutex
			runs []time.Time
		)
		period := &atomic.Int64{}
		period.Store(int64(60 * time.Second))
		count := func() int {
			mu.Lock()
			defer mu.Unlock()
			return len(runs)
		}
		tr := newTestTrigger(t, TriggerConfig{
			Debounce: time.Second,
			Run: func(_ context.Context, trigger string) error {
				if trigger != TriggerPeriodic {
					t.Errorf("periodic run trigger = %q, want %q", trigger, TriggerPeriodic)
				}
				mu.Lock()
				runs = append(runs, time.Now())
				mu.Unlock()
				return nil
			},
			Interval: func() time.Duration { return time.Duration(period.Load()) },
		})
		tr.Start()
		defer stopTrigger(t, tr)

		time.Sleep(62 * time.Second) // tick at 60, one debounce later the run at 61
		synctest.Wait()
		if got := count(); got != 1 {
			t.Fatalf("periodic runs after one period = %d, want 1", got)
		}

		period.Store(int64(30 * time.Second))
		time.Sleep(90 * time.Second) // t=152: next runs at 121 (old period) then 151 (new period)
		synctest.Wait()

		mu.Lock()
		defer mu.Unlock()
		if len(runs) != 3 {
			t.Fatalf("periodic runs = %d, want 3 (the changed interval must be used)", len(runs))
		}
		if gap := runs[2].Sub(runs[1]); gap != 30*time.Second {
			t.Fatalf("gap after the interval change = %s, want 30s", gap)
		}
	})
}

// A periodic tick that lands inside a webhook debounce window is the same signal and must not
// produce a second, back-to-back run (review F1-013 finding 1). The burst keeps the webhook label
// because webhook outranks periodic (Y-05.2).
func TestTrigger_PeriodicMergesIntoDebounce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var (
			mu       sync.Mutex
			triggers []string
		)
		tr := newTestTrigger(t, TriggerConfig{
			Debounce: 3 * time.Second,
			Interval: func() time.Duration { return 2 * time.Second },
			Run: func(_ context.Context, trigger string) error {
				mu.Lock()
				triggers = append(triggers, trigger)
				mu.Unlock()
				return nil
			},
		})
		tr.Start()
		defer stopTrigger(t, tr)

		tr.Signal() // t=0: opens a 3s debounce window
		time.Sleep(3500 * time.Millisecond)
		synctest.Wait()

		mu.Lock()
		defer mu.Unlock()
		if len(triggers) != 1 {
			t.Fatalf("reconcile runs = %d, want 1 (the periodic tick must merge into the webhook burst)", len(triggers))
		}
		if triggers[0] != TriggerWebhook {
			t.Fatalf("merged burst trigger = %q, want %q (webhook outranks periodic)", triggers[0], TriggerWebhook)
		}
	})
}

// AC4: a signal that arrives while a reconcile runs causes exactly one more run afterwards.
func TestTrigger_CoalesceDuringRun(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		gate := make(chan struct{})
		var starts atomic.Int32
		tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error {
			starts.Add(1)
			<-gate
			return nil
		}})
		tr.Start()
		defer stopTrigger(t, tr)

		tr.Signal()
		time.Sleep(DefaultDebounce)
		synctest.Wait() // the first run is in progress, blocked on gate

		tr.Signal()
		tr.Signal()
		gate <- struct{}{} // let the first run finish

		time.Sleep(DefaultDebounce) // the queued signals run once more
		synctest.Wait()
		gate <- struct{}{} // let the second run finish
		synctest.Wait()

		if got := starts.Load(); got != 2 {
			t.Fatalf("reconcile runs = %d, want 2 (signals during a run coalesce into one more)", got)
		}
	})
}

// AC5: shutdown waits for the running reconcile, and gives up after the timeout.
func TestTrigger_GracefulShutdown(t *testing.T) {
	t.Run("waits for the running reconcile", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			gate := make(chan struct{})
			runDone := make(chan struct{})
			tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error {
				<-gate
				close(runDone)
				return nil
			}})
			tr.Start()
			tr.Signal()
			time.Sleep(DefaultDebounce)
			synctest.Wait() // the run is blocked on gate

			stopped := make(chan error, 1)
			go func() { stopped <- tr.Stop() }()
			synctest.Wait()

			select {
			case <-runDone:
				t.Fatal("the run finished before it was released")
			default:
			}
			select {
			case err := <-stopped:
				t.Fatalf("Stop returned before the running reconcile finished: %v", err)
			default:
			}

			gate <- struct{}{}
			synctest.Wait()

			select {
			case err := <-stopped:
				if err != nil {
					t.Fatalf("Stop: %v", err)
				}
			default:
				t.Fatal("Stop did not return after the running reconcile finished")
			}
		})
	})

	t.Run("gives up after the timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			tr := newTestTrigger(t, TriggerConfig{
				Run: func(ctx context.Context, _ string) error {
					<-ctx.Done()
					return ctx.Err()
				},
				ShutdownTimeout: 5 * time.Second,
			})
			tr.Start()
			tr.Signal()
			time.Sleep(DefaultDebounce)
			synctest.Wait()

			stopped := make(chan error, 1)
			go func() { stopped <- tr.Stop() }()
			time.Sleep(6 * time.Second)
			synctest.Wait()

			select {
			case err := <-stopped:
				if err == nil {
					t.Fatal("Stop returned nil, want a timeout error")
				}
			default:
				t.Fatal("Stop did not return after the shutdown timeout")
			}
		})
	})

	// After the timeout, Stop cancels but must not return before the canceled run has unwound: a
	// caller that closes the store/clients afterwards would otherwise cut off post-write bookkeeping.
	t.Run("waits for the canceled reconcile to unwind", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var unwound atomic.Bool
			finish := make(chan struct{})
			tr := newTestTrigger(t, TriggerConfig{
				Run: func(ctx context.Context, _ string) error {
					<-ctx.Done()
					unwound.Store(true)
					<-finish
					return ctx.Err()
				},
				ShutdownTimeout: 5 * time.Second,
			})
			tr.Start()
			tr.Signal()
			time.Sleep(DefaultDebounce)
			synctest.Wait()

			stopped := make(chan error, 1)
			go func() { stopped <- tr.Stop() }()
			time.Sleep(5 * time.Second) // the graceful window expires, the run unwinds and blocks
			synctest.Wait()
			if !unwound.Load() {
				t.Fatal("the run was not canceled after the timeout")
			}
			select {
			case err := <-stopped:
				t.Fatalf("Stop returned before the canceled reconcile unwound: %v", err)
			default:
			}

			close(finish)
			synctest.Wait()
			select {
			case err := <-stopped:
				if err == nil {
					t.Fatal("Stop returned nil, want a timeout error")
				}
			default:
				t.Fatal("Stop did not return after the reconcile unwound")
			}
		})
	})
}

func TestNewTrigger_RequiresRun(t *testing.T) {
	if _, err := NewTrigger(TriggerConfig{}); err == nil {
		t.Fatal("NewTrigger accepted a nil run function")
	}
}

// The trigger label is recorded on the run (Y-05.2): a signal is a webhook, Request carries its own.
func TestTrigger_RecordsTrigger(t *testing.T) {
	cases := []struct {
		name string
		send func(*Trigger)
		want string
	}{
		{"webhook", func(tr *Trigger) { tr.Signal() }, TriggerWebhook},
		{"manual", func(tr *Trigger) { tr.Request(TriggerManual) }, TriggerManual},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				got := make(chan string, 1)
				tr := newTestTrigger(t, TriggerConfig{Run: func(_ context.Context, trigger string) error {
					got <- trigger
					return nil
				}})
				tr.Start()
				defer stopTrigger(t, tr)

				tc.send(tr)
				time.Sleep(DefaultDebounce)
				synctest.Wait()

				select {
				case trigger := <-got:
					if trigger != tc.want {
						t.Fatalf("trigger = %q, want %q", trigger, tc.want)
					}
				default:
					t.Fatal("no reconcile ran")
				}
			})
		})
	}
}

func TestTrigger_IgnoresUnknownRequest(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error {
			calls.Add(1)
			return nil
		}})
		tr.Start()
		defer stopTrigger(t, tr)

		tr.Request("bogus")
		time.Sleep(DefaultDebounce)
		synctest.Wait()
		if got := calls.Load(); got != 0 {
			t.Fatalf("reconcile runs = %d, want 0 for an unknown trigger", got)
		}
	})
}

// A second Start must not launch a second reconcile loop (that would double runs and close the
// done channel twice); synctest fails the test if a leaked goroutine remains.
func TestTrigger_StartIdempotent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error {
			calls.Add(1)
			return nil
		}})
		tr.Start()
		tr.Start()
		defer stopTrigger(t, tr)

		tr.Signal()
		time.Sleep(DefaultDebounce)
		synctest.Wait()
		if got := calls.Load(); got != 1 {
			t.Fatalf("reconcile runs = %d, want 1 after a doubled Start", got)
		}
	})
}

// Stop before Start must return at once instead of waiting for the shutdown timeout.
func TestTrigger_StopBeforeStart(t *testing.T) {
	tr := newTestTrigger(t, TriggerConfig{Run: func(context.Context, string) error { return nil }})
	if err := tr.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
}

// The periodic interval comes from a stored setting; a missing, malformed or out-of-range value
// must fall back to the default instead of disabling or busy-looping the scheduler (F1-017 AC7).
func TestIntervalFromSetting(t *testing.T) {
	def := 7 * time.Minute
	cases := []struct {
		name  string
		value string
		want  time.Duration
	}{
		{"empty", "", def},
		{"minimum", "1", time.Minute},
		{"default value", "5", 5 * time.Minute},
		{"maximum", "60", 60 * time.Minute},
		{"zero is out of range", "0", def},
		{"above maximum", "61", def},
		{"negative", "-3", def},
		{"not a number", "5m", def},
		{"whitespace is trimmed", " 15 ", 15 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IntervalFromSetting(tc.value, def); got != tc.want {
				t.Fatalf("IntervalFromSetting(%q) = %s, want %s", tc.value, got, tc.want)
			}
		})
	}
}

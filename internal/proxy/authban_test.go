package proxy

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"proxygw/internal/auth"
	"proxygw/internal/model"
)

type authBanClock struct{ now time.Time }

func (c *authBanClock) Now() time.Time          { return c.now }
func (c *authBanClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestAuthBanTracker(t *testing.T, cfg AuthBanConfig) (*AuthBanTracker, *authBanClock) {
	t.Helper()
	clk := &authBanClock{now: time.Unix(1700000000, 0).UTC()}
	tr := NewAuthBanTracker(cfg)
	if tr == nil {
		t.Fatal("NewAuthBanTracker returned nil")
	}
	tr.now = clk.Now
	return tr, clk
}

func TestAuthBanThresholdAndExpiry(t *testing.T) {
	tr, clk := newTestAuthBanTracker(t, AuthBanConfig{
		Enabled:          true,
		FailureWindow:    time.Minute,
		FailureThreshold: 3,
		BanDuration:      10 * time.Minute,
		MaxEntries:       64,
	})
	const ip = "203.0.113.9"
	for i := 0; i < 2; i++ {
		banned, _, failures := tr.RecordFailure(ip, reasonBadCredential)
		if banned || failures != i+1 {
			t.Fatalf("failure %d banned=%v failures=%d", i+1, banned, failures)
		}
	}
	banned, banFor, failures := tr.RecordFailure(ip, reasonBadCredential)
	if !banned || banFor != 10*time.Minute || failures != 3 {
		t.Fatalf("threshold ban=%v for=%v failures=%d", banned, banFor, failures)
	}
	remaining, blocked := tr.Blocked(ip)
	if !blocked || remaining != 10*time.Minute {
		t.Fatalf("Blocked = %v/%v, want 10m", remaining, blocked)
	}
	snapshot := tr.Snapshot()
	if len(snapshot) != 1 || snapshot[0].Failures != 3 || snapshot[0].Reason != reasonBadCredential {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if !tr.Unban(ip) {
		t.Fatal("Unban returned false")
	}
	if _, blocked := tr.Blocked(ip); blocked {
		t.Fatal("source still blocked after Unban")
	}

	// A fresh window allows a new failure sequence; expiry of the ban itself
	// also clears it without an explicit Unban.
	for i := 0; i < 3; i++ {
		tr.RecordFailure(ip, reasonNoCredential)
	}
	if _, blocked := tr.Blocked(ip); !blocked {
		t.Fatal("repeated failures did not re-ban")
	}
	clk.Advance(10 * time.Minute)
	if _, blocked := tr.Blocked(ip); blocked {
		t.Fatal("expired ban still blocks")
	}
}

func TestAuthBanWindowAndSuccessReset(t *testing.T) {
	tr, clk := newTestAuthBanTracker(t, AuthBanConfig{
		Enabled:          true,
		FailureWindow:    time.Minute,
		FailureThreshold: 2,
		BanDuration:      time.Minute,
		MaxEntries:       64,
	})
	const ip = "203.0.113.10"
	tr.RecordFailure(ip, reasonBadCredential)
	tr.RecordSuccess(ip)
	if banned, _, _ := tr.RecordFailure(ip, reasonBadCredential); banned {
		t.Fatal("success did not reset failure count")
	}
	// A failure older than the window is dropped, so two separated failures do
	// not add up to a ban.
	clk.Advance(2 * time.Minute)
	if banned, _, _ := tr.RecordFailure(ip, reasonBadCredential); banned {
		t.Fatal("old failure was still counted")
	}
}

func TestAuthBanExemptLoopbackAndCIDR(t *testing.T) {
	tr, _ := newTestAuthBanTracker(t, AuthBanConfig{
		Enabled:          true,
		FailureWindow:    time.Minute,
		FailureThreshold: 1,
		BanDuration:      time.Minute,
		MaxEntries:       64,
		Exempt:           []string{"198.51.100.0/24"},
	})
	for _, ip := range []string{"127.0.0.1", "::1", "198.51.100.7"} {
		if banned, _, _ := tr.RecordFailure(ip, reasonAuthMalformed); banned {
			t.Fatalf("exempt IP %s was banned", ip)
		}
		if _, blocked := tr.Blocked(ip); blocked {
			t.Fatalf("exempt IP %s is blocked", ip)
		}
	}
	if banned, _, _ := tr.RecordFailure("203.0.113.11", reasonAuthMalformed); !banned {
		t.Fatal("non-exempt IP was not banned")
	}
}

func TestAuthBanIPv6CanonicalKey(t *testing.T) {
	tr, _ := newTestAuthBanTracker(t, AuthBanConfig{
		Enabled:          true,
		FailureWindow:    time.Minute,
		FailureThreshold: 1,
		BanDuration:      time.Minute,
		MaxEntries:       64,
	})
	if banned, _, _ := tr.RecordFailure("2001:0db8::1", reasonBadCredential); !banned {
		t.Fatal("IPv6 failure did not ban")
	}
	if _, blocked := tr.Blocked("2001:db8::1"); !blocked {
		t.Fatal("IPv6 canonical form did not match the ban")
	}
	if !tr.Unban("2001:db8::1") {
		t.Fatal("Unban IPv6 returned false")
	}
}

func TestAuthBanDisabledReturnsNil(t *testing.T) {
	if tr := NewAuthBanTracker(AuthBanConfig{Enabled: false}); tr != nil {
		t.Fatal("disabled tracker must be nil")
	}
	var tr *AuthBanTracker
	if _, blocked := tr.Blocked("203.0.113.1"); blocked {
		t.Fatal("nil tracker blocked")
	}
	if banned, _, _ := tr.RecordFailure("203.0.113.1", reasonBadCredential); banned {
		t.Fatal("nil tracker banned")
	}
}

// authBanTestAuthenticator returns a fixed error so the classification branch
// in verifyCredential can be exercised without the credential store.
type authBanTestAuthenticator struct {
	err   error
	calls int
}

func (a *authBanTestAuthenticator) Verify(string, string) (*model.Credential, error) {
	a.calls++
	if a.err != nil {
		return nil, a.err
	}
	return testCredential("cred-1", "alice"), nil
}

func basicAuthHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAuthBanPipelineCountsOnlyCredentialGuesses(t *testing.T) {
	tracker := NewAuthBanTracker(AuthBanConfig{
		Enabled:          true,
		FailureWindow:    time.Minute,
		FailureThreshold: 4,
		BanDuration:      time.Minute,
		MaxEntries:       64,
	})
	authn := &authBanTestAuthenticator{err: errors.New("wrong password")}
	opts := baseOptions()
	opts.AuthMode = model.AuthRequired
	opts.Authenticator = authn
	opts.Candidates = newFakeCandidates()
	opts.Selector = &fakeSelector{}
	opts.Dialer = &fakeDialer{}
	opts.AuthBan = tracker
	p, err := newPipeline(opts)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	const ip = "203.0.113.50"
	bad := basicAuthHeader("alice", "wrong")
	for i := 0; i < 2; i++ {
		if cred, perr := p.authenticateHTTP(bad, ip, model.ProtoHTTP); cred != nil || perr == nil {
			t.Fatalf("bad auth %d = %+v/%v", i, cred, perr)
		}
	}
	// Missing and malformed headers are countable too.
	if _, perr := p.authenticateHTTP("", ip, model.ProtoHTTP); perr == nil || perr.reason != reasonNoCredential {
		t.Fatalf("missing credential reason = %+v", perr)
	}
	if _, blocked := tracker.Blocked(ip); blocked {
		t.Fatal("source banned before the configured threshold")
	}
	if _, perr := p.authenticateHTTP("Digest abc", ip, model.ProtoHTTP); perr == nil {
		t.Fatal("malformed auth was accepted")
	}
	if _, blocked := tracker.Blocked(ip); !blocked {
		t.Fatal("source was not banned after the threshold")
	}
	if calls := authn.calls; calls != 2 {
		t.Fatalf("authenticator calls = %d, want 2 (no credential/malformed must not reach Verify)", calls)
	}
}

func TestAuthBanPipelineDoesNotCountDisabledOrExpired(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"disabled", &auth.VerifyError{Kind: auth.VerifyDisabled, Username: "alice"}},
		{"expired", &auth.VerifyError{Kind: auth.VerifyExpired, Username: "alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewAuthBanTracker(AuthBanConfig{
				Enabled:          true,
				FailureWindow:    time.Minute,
				FailureThreshold: 1,
				BanDuration:      time.Minute,
				MaxEntries:       64,
			})
			authn := &authBanTestAuthenticator{err: tc.err}
			opts := baseOptions()
			opts.AuthMode = model.AuthRequired
			opts.Authenticator = authn
			opts.Candidates = newFakeCandidates()
			opts.Selector = &fakeSelector{}
			opts.Dialer = &fakeDialer{}
			opts.AuthBan = tracker
			p, err := newPipeline(opts)
			if err != nil {
				t.Fatalf("newPipeline: %v", err)
			}
			if _, perr := p.authenticateHTTP(basicAuthHeader("alice", "x"), "203.0.113.51", model.ProtoHTTP); perr == nil {
				t.Fatal("disabled/expired credential was accepted")
			}
			if _, blocked := tracker.Blocked("203.0.113.51"); blocked {
				t.Fatal("disabled/expired credential caused an IP ban")
			}
		})
	}
}

// Package acl implements the ordered access control engine and the built-in
// forced deny list of proxygw (ACL design G.1/G.2).
//
// Evaluation order is fixed and cannot be changed by configuration:
//
//  1. The built-in forced deny list is evaluated first. Loopback, private,
//     link-local, unique-local, unspecified and CGNAT addresses, the cloud
//     metadata endpoints, loopback host names and a set of high risk ports are
//     always denied. Operator rules cannot disable or override this list; they
//     can only add further restrictions.
//  2. Operator rules are matched in ascending Order (configuration order for
//     equal values). Every non-empty dimension of a rule must match: source
//     CIDRs, target host (domain or IP/CIDR), ports and protocols. The first
//     matching rule decides the request and stops the scan.
//  3. When no rule matches, the dynamic default action returned by
//     Options.DefaultAction (normally Settings().DefaultACLAction) is applied.
//     Values other than "allow"/"deny" are treated as allow and reported by
//     Explain.
//
// The engine never performs DNS resolution: a target host that is a domain is
// matched against domain rules as a literal string only, so the forced IP list
// can only reject IP literals here. The node side must repeat the address
// checks after resolving the target name.
//
// Test-only escape hatch: setting NP_ACL_ALLOW_LOOPBACK_TARGETS=1 in the
// environment (or Options.AllowLoopbackTargets) exempts loopback, private,
// link-local and unique-local addresses, loopback host names and the high risk
// port list from the forced deny list, so in-process automated tests can reach
// local servers. Cloud metadata endpoints, unspecified addresses and CGNAT
// ranges stay blocked and the switch must never be enabled in production.
package acl

import (
	"os"
	"strings"
	"sync"

	"proxygw/internal/model"
)

// loopbackTargetsEnv is the test-only environment switch that exempts local
// test targets from the forced deny list. See the package documentation.
const loopbackTargetsEnv = "NP_ACL_ALLOW_LOOPBACK_TARGETS"

// Options configures an Engine. The zero value is usable.
type Options struct {
	// DefaultAction returns the current default ACL action, normally
	// Settings().DefaultACLAction. It is consulted for every request that does
	// not match a rule, so hot reloaded settings apply immediately. nil means
	// allow. A panicking provider is recovered and treated as allow so the
	// request path never panics.
	DefaultAction func() string

	// AllowLoopbackTargets exempts loopback, private, link-local and unique-local
	// addresses, loopback host names and the high risk port list from the
	// forced deny list. It exists for automated in-process tests only and must
	// stay false in production. Cloud metadata endpoints, unspecified addresses
	// and CGNAT ranges remain blocked. The NP_ACL_ALLOW_LOOPBACK_TARGETS=1
	// environment variable is equivalent and is evaluated by New.
	AllowLoopbackTargets bool
}

// Engine is a concurrency safe ACL evaluator. SetRules atomically replaces the
// compiled rule set; Check and Explain take only a short read lock on the
// current snapshot and never compile rules on the request path. The zero value
// is ready to use: no rules, default allow, forced deny list enforced.
type Engine struct {
	mu    sync.RWMutex
	rules []compiledRule
	raw   []model.ACLRule

	defaultAction    func() string
	allowTestTargets bool
}

// New returns an Engine with no user rules.
func New(opts Options) *Engine {
	return &Engine{
		defaultAction:    opts.DefaultAction,
		allowTestTargets: opts.AllowLoopbackTargets || envAllowsLoopbackTargets(),
	}
}

func envAllowsLoopbackTargets() bool {
	v := strings.TrimSpace(os.Getenv(loopbackTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// SetRules validates and compiles the operator rules, then atomically replaces
// the current rule set. Rules are sorted by ascending Order (stable for ties).
// The replacement is atomic: when validation fails the previous rule set stays
// in effect and the returned error names the offending rule, field and value.
func (e *Engine) SetRules(rules []model.ACLRule) error {
	compiled, raw, err := compileRules(rules)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.rules = compiled
	e.raw = raw
	e.mu.Unlock()
	return nil
}

// Rules returns a deep copy of the current operator rules in evaluation order
// (ascending Order). The result is never nil so panel JSON renders [].
func (e *Engine) Rules() []model.ACLRule {
	e.mu.RLock()
	raw := e.raw
	e.mu.RUnlock()
	return cloneRules(raw)
}

// Check evaluates the target and returns nil when the request is allowed. A
// denied request returns an error of type *DeniedError.
func (e *Engine) Check(t model.RequestTarget) error {
	v := e.evaluate(t)
	if v.allowed {
		return nil
	}
	return &DeniedError{RuleID: v.ruleID, Forced: v.forced, Reason: explainReason(v)}
}

// Explain evaluates the target for panel previews. It reports the same decision
// as Check plus the matching rule, whether a forced rule decided, and a
// human-readable reason.
func (e *Engine) Explain(t model.RequestTarget) Decision {
	v := e.evaluate(t)
	return Decision{Allowed: v.allowed, RuleID: v.ruleID, Forced: v.forced, Reason: explainReason(v)}
}

// Decision is the readable result of Explain. RuleID names the operator rule or
// the forced rule that decided the request; it is empty when the default action
// decided.
type Decision struct {
	Allowed bool   `json:"allowed"`
	RuleID  string `json:"rule_id"`
	Forced  bool   `json:"forced"`
	Reason  string `json:"reason"`
}

// DeniedError is returned by Check when a request is denied. Forced reports
// whether the built-in forced deny list rejected the request; such decisions
// cannot be reverted from the panel or by adding allow rules.
type DeniedError struct {
	RuleID string `json:"rule_id"`
	Forced bool   `json:"forced"`
	Reason string `json:"reason"`
}

// Error implements error.
func (d *DeniedError) Error() string {
	if d == nil {
		return "acl: denied"
	}
	if d.Reason != "" {
		return "acl: " + d.Reason
	}
	if d.Forced {
		return "acl: denied by forced rule " + d.RuleID
	}
	if d.RuleID != "" {
		return "acl: denied by rule " + d.RuleID
	}
	return "acl: denied"
}

var _ error = (*DeniedError)(nil)

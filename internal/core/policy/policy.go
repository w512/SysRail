// Package policy decides whether an agent may use a permission on a resource.
//
// Semantics:
//   - any matching deny rule wins;
//   - otherwise the most specific matching rule decides between allow and ask
//     (resource name > resource glob > exact permission > domain wildcard > "*"),
//     with ask winning ties;
//   - if nothing matches, the request is denied.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Action is a policy outcome.
type Action string

const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Deny  Action = "deny"
)

func (a Action) valid() bool { return a == Allow || a == Ask || a == Deny }

// File is the on-disk policy document.
type File struct {
	Version int                    `yaml:"version"`
	Agents  map[string]AgentPolicy `yaml:"agents"`
}

// AgentPolicy lists permission grants for one agent. Resources maps
// kind -> resource name or glob -> verb (or full permission) -> action.
type AgentPolicy struct {
	Allow     []string                                `yaml:"allow"`
	Ask       []string                                `yaml:"ask"`
	Deny      []string                                `yaml:"deny"`
	Resources map[string]map[string]map[string]Action `yaml:"resources"`
}

// Parse decodes a policy document, rejecting unknown fields.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &f, nil
}

// Reserved lists permission categories from the spec (Appendix A) that may be
// referenced by policy even before a capability implements them.
var Reserved = []string{
	"system.read", "system.update",
	"apps.read", "apps.start", "apps.stop", "apps.restart", "apps.update",
	"logs.read",
	"storage.read", "storage.modify",
	"files.read", "files.write", "files.delete",
	"network.read", "network.modify",
	"users.read", "users.modify",
	"ai.read", "ai.manage",
	"shell.exec",
}

// Known describes what a policy may reference.
type Known struct {
	// Agents configured with credentials. Nil disables the check.
	Agents map[string]bool
	// Permissions used by registered capabilities, mapped to the resource
	// kinds each can be scoped to.
	Permissions map[string]map[string]bool
}

const (
	specAll      = 0
	specDomain   = 10
	specExact    = 20
	specGlob     = 30
	specResource = 40
)

type rule struct {
	action      Action
	permission  string // exact, "<domain>.*" or "*"
	kind        string // resource kind for resource rules
	resource    string // resource name or glob
	specificity int
	source      string
}

func (r *rule) matches(permission, kind, resource string) bool {
	if r.kind != "" {
		if r.kind != kind || r.permission != permission || resource == "" {
			return false
		}
		if r.specificity == specResource {
			return r.resource == resource
		}
		ok, _ := path.Match(r.resource, resource)
		return ok
	}
	return permissionMatches(r.permission, permission)
}

func permissionMatches(pattern, permission string) bool {
	switch {
	case pattern == "*":
		return true
	case strings.HasSuffix(pattern, ".*"):
		return strings.HasPrefix(permission, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == permission
}

// Policy is a compiled, validated policy.
type Policy struct {
	agents map[string][]rule
}

// Decision is the outcome of evaluating a request.
type Decision struct {
	Action Action
	// Rule describes the rule that produced the decision, for auditing.
	Rule string
}

// Compile validates f against known and builds an evaluable policy.
func Compile(f *File, known Known) (*Policy, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d (want 1)", f.Version)
	}
	perms := map[string]map[string]bool{}
	for _, p := range Reserved {
		perms[p] = map[string]bool{}
	}
	for p, kinds := range known.Permissions {
		perms[p] = kinds
	}
	domains := map[string]bool{}
	for p := range perms {
		domains[strings.SplitN(p, ".", 2)[0]] = true
	}

	p := &Policy{agents: map[string][]rule{}}
	var errs []error
	names := make([]string, 0, len(f.Agents))
	for name := range f.Agents {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ap := f.Agents[name]
		fail := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("policy: agent %q: %s", name, fmt.Sprintf(format, args...)))
		}
		if known.Agents != nil && !known.Agents[name] {
			fail("not configured in agents")
		}
		var rules []rule
		seen := map[string]Action{}
		for _, list := range []struct {
			action Action
			items  []string
		}{{Deny, ap.Deny}, {Ask, ap.Ask}, {Allow, ap.Allow}} {
			for _, item := range list.items {
				spec, err := checkPermissionPattern(item, perms, domains)
				if err != nil {
					fail("%s: %v", list.action, err)
					continue
				}
				if prev, dup := seen[item]; dup {
					fail("%q is listed under both %s and %s", item, prev, list.action)
					continue
				}
				seen[item] = list.action
				rules = append(rules, rule{
					action: list.action, permission: item, specificity: spec,
					source: fmt.Sprintf("%s: %s %s", name, list.action, item),
				})
			}
		}
		for _, kind := range sortedKeys(ap.Resources) {
			for _, res := range sortedKeys(ap.Resources[kind]) {
				spec := specResource
				if strings.ContainsAny(res, "*?[") {
					spec = specGlob
				}
				if res == "" {
					fail("resources.%s: empty resource name", kind)
					continue
				}
				if _, err := path.Match(res, ""); err != nil {
					fail("resources.%s: bad pattern %q", kind, res)
					continue
				}
				for _, verb := range sortedKeys(ap.Resources[kind][res]) {
					action := ap.Resources[kind][res][verb]
					perm := verb
					if !strings.Contains(verb, ".") {
						perm = kind + "." + verb
					}
					if !action.valid() {
						fail("resources.%s[%q].%s: unknown action %q", kind, res, verb, action)
						continue
					}
					if !perms[perm][kind] {
						fail("resources.%s[%q]: %s cannot be scoped to %s resources", kind, res, perm, kind)
						continue
					}
					rules = append(rules, rule{
						action: action, permission: perm, kind: kind, resource: res, specificity: spec,
						source: fmt.Sprintf("%s: resources.%s[%s].%s=%s", name, kind, res, verb, action),
					})
				}
			}
		}
		p.agents[name] = rules
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return p, nil
}

func checkPermissionPattern(item string, perms map[string]map[string]bool, domains map[string]bool) (int, error) {
	switch {
	case item == "*":
		return specAll, nil
	case strings.HasSuffix(item, ".*"):
		domain := strings.TrimSuffix(item, ".*")
		if !domains[domain] {
			return 0, fmt.Errorf("unknown permission domain %q", item)
		}
		return specDomain, nil
	case perms[item] != nil:
		return specExact, nil
	}
	return 0, fmt.Errorf("unknown permission %q", item)
}

// Decide evaluates a request. kind and resource may be empty.
func (p *Policy) Decide(agent, permission, kind, resource string) Decision {
	rules, ok := p.agents[agent]
	if !ok {
		return Decision{Action: Deny, Rule: "no policy for agent"}
	}
	var best *rule
	for i := range rules {
		r := &rules[i]
		if !r.matches(permission, kind, resource) {
			continue
		}
		if r.action == Deny {
			return Decision{Action: Deny, Rule: r.source}
		}
		if best == nil || r.specificity > best.specificity ||
			(r.specificity == best.specificity && r.action == Ask) {
			best = r
		}
	}
	if best == nil {
		return Decision{Action: Deny, Rule: "default deny"}
	}
	return Decision{Action: best.action, Rule: best.source}
}

// Reachable reports whether agent could ever be allowed or asked for
// permission on some resource. Used to hide tools that would always be denied.
func (p *Policy) Reachable(agent, permission string) bool {
	rules := p.agents[agent]
	granted := false
	for _, r := range rules {
		if r.kind == "" && permissionMatches(r.permission, permission) && r.action == Deny {
			return false
		}
		if r.action != Deny && (r.kind == "" && permissionMatches(r.permission, permission) ||
			r.kind != "" && r.permission == permission) {
			granted = true
		}
	}
	return granted
}

// Agents returns the names of agents with a policy.
func (p *Policy) Agents() []string {
	names := make([]string, 0, len(p.agents))
	for n := range p.agents {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

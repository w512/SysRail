# Security policy

SysRail is a security boundary between AI agents and a Linux host, so
vulnerabilities in it matter. Thank you for reporting them responsibly.

## Reporting a vulnerability

Email **Nick Blokhin <nick@blokhin.us>** with "SysRail security" in the
subject. Please don't open a public issue for security problems.

Include as much of the following as you can:

- What an attacker can do: for example, bypass policy or approval, run
  something that was not allowed, read data they should not see, or avoid the
  audit log.
- Which component is affected (daemon, `sysrail mcp`, policy, a provider, the
  systemd unit, the install scripts) and the commit or version.
- Steps or a proof of concept to reproduce it, and your configuration and
  policy if they are relevant.

You can expect an acknowledgement within a week. The fix is developed
privately and released together with an advisory. With your permission,
you'll be credited.

## Supported versions

SysRail is pre-1.0. Security fixes go into the latest release and the
`master` branch only. Please make sure you can reproduce the problem there.

## Scope

In scope: anything that lets an agent, or anyone without admin access to the
host, exceed what the configured policy and polkit rule allow. That includes
policy or approval bypasses, injection into service names or helper commands,
access to another agent's requests or events, missing audit records, and
secret leaks that the redaction rules claim to cover.

Out of scope are the documented limitations in
[docs/security.md](docs/security.md#what-sysrail-does-not-protect-against).
An example is an agent that can bypass SysRail because its host also gives it
a shell.

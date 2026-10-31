# Security policy

pvewarden sits between an AI agent and your servers, so security reports are very welcome.

## Reporting a vulnerability

Please report it privately: **Security → Report a vulnerability** on GitHub
(<https://github.com/matousfiser/pvewarden/security/advisories/new>). Please don't open a public
issue.

Useful to include: the version, what an attacker needs (a token, network access, a compromised
guest, …), what they can reach, and steps to reproduce.

You'll get an answer within a week. Fixes go into a new release, and the advisory is published once
users can update.

## Supported versions

Only the latest release gets security fixes.

## Scope

In scope, among others:
- ways for an agent to go beyond the guest's tags, the pool or the confirmation dialogs,
- ways to run commands on a guest other than the fixed ones,
- leaks of the Proxmox token, agent tokens or the SSH key,
- weaknesses in what `pvewarden-setup` creates.

The model is described in [docs/security.md](docs/security.md). Some things are out of scope by
design: an agent doing harmful things that its tags allow, and a holder of a valid token acting as
that agent.

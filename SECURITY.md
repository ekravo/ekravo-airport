# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Report it privately to the maintainers through GitHub's private vulnerability
reporting on `ekravo/ekravo-airport` (Security → Report a vulnerability), or by email to
`security@ekravo.com` if that is unavailable.

Include:

- The affected version or commit.
- A description of the impact.
- Reproduction steps or a proof of concept.
- Any suggested fix.

We aim to acknowledge within three business days and to publish a fix and
advisory for confirmed issues.

## Scope

In scope:

- Authentication and authorization bypasses.
- Cross-account device or message access.
- Credential, ticket, or pairing-code weaknesses.
- Denial of service through unbounded resource use.
- Payload or secret leakage through logs, errors, or URLs.
- Flaws in the E2EE construction or its interoperability.

Out of scope:

- A device that intentionally exposes dangerous events (a remote shell built on
  top of Airport).
- Compromise of the host, the database, or the operator's `.env`.
- Missing hardening that is documented as an operator responsibility.
- Denial of service from an attacker with unlimited bandwidth against a
  single-node deployment beyond the documented limits.

See [docs/security.md](docs/security.md) for the threat model.

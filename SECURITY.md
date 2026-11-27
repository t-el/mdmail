# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them
privately through GitHub's *Report a vulnerability* button on the repository's
**Security** tab (private vulnerability reporting), including:

- affected version / commit,
- a description of the issue and its impact,
- steps to reproduce or a proof of concept.

You will receive an acknowledgement within 72 hours. Fixes are released as
soon as practical, and reporters are credited unless they prefer otherwise.

## Supported versions

Only the latest release on `main` receives security fixes.

## Scope

In scope: the `mdmail` binary, its web client, the Docker image and the
default `docker-compose.yml`. Out of scope: vulnerabilities requiring a
compromised host, operator misconfiguration contrary to
[docs/security.md](docs/security.md), and denial of service by volumetric
network floods.

See [docs/security.md](docs/security.md) for the security model.

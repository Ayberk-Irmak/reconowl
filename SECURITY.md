# Security Policy

## Reporting a vulnerability in reconowl

If you find a security issue **in reconowl itself** (for example, a way the tool
could harm the machine it runs on, leak captured data, or send traffic to an
unintended host), please report it privately:

- Open a [private security advisory](https://github.com/Ayberk-Irmak/reconowl/security/advisories/new), or
- Email the maintainer.

Please do **not** open a public issue for security reports. We aim to acknowledge
reports within a few days.

## Scope

This policy covers the reconowl codebase. It does **not** cover findings that
reconowl produces about *your* targets — those are yours to triage.

## Responsible use

reconowl performs active scanning and light exploitation probing. Use it only
against systems you own or are explicitly authorized in writing to test.
Unauthorized scanning is illegal in most jurisdictions. See `NOTICE`.

## Supported versions

The latest released version on [PyPI](https://pypi.org/project/reconowl/)
receives fixes. Older versions are not maintained.

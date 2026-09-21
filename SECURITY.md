# Security policy

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Report it
privately through [GitHub Security Advisories](https://github.com/jad-fahmi/iocforge-lab/security/advisories/new)
or email the repository owner. Include reproduction steps, affected versions,
and the likely impact. We aim to acknowledge reports within five business days.

## Scope and data handling

IOCForge processes indicators supplied by analysts and sends them to enabled
third-party intelligence providers. Do not submit credentials, customer data,
or other secrets as indicators. API keys belong in environment variables or
the local configuration file and must never be committed.

## Supported versions

Security fixes are applied to the current `main` branch until formal releases
are introduced.

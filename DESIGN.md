# Devicegrove: design for a future monitor

This document describes work that has **not** been implemented. The current
prototype is a one-shot local collector, not a fleet monitor.

## Boundaries

Collect only disclosed security posture measurements with the device owner's
knowledge. Do not collect personal files, browsing, keystrokes, screenshots,
arbitrary app inventories or unrelated activity. Do not provide remote
commands, remote control or device wiping. Keep ownership and roster data
separate from the minimal evidence, with explicit access controls and
retention. Never infer compliance from missing data or a stale check-in.

## Identity and transport

Design consent-based enrollment that binds a random per-install device ID to
an authorized owner and a device-held non-exportable key. Keep the owner mapping
separately restricted; include key rotation, revocation, duplicate enrollment
and recovery. Use authenticated TLS, server certificate verification,
per-device authentication, replay protection, payload bounds and rate limits.
Do not use a shared static secret as a device identity. Even a signed report is
not proof that a compromised device made a truthful measurement.

## Evidence and remediation

An independently maintained in-scope inventory must reveal devices that never
enrolled or checked in. Record server receipt time separately from local
observation time, alongside collector and policy versions, minimal measurements
and explicit failures or unknowns. Calculate staleness from server receipt time
using an agreed threshold; monitor the monitoring service itself.

Preserve append-only history through changes and remediation, with restricted,
audited access, encryption at rest, tested backups, retention and deletion rules.
Handle duplicate and out-of-order submissions without losing past failures.
Track each failure, unknown or stale device with an owner, dates, action and,
where needed, an approved time-limited exception. Close only on fresh evidence
or an approved exception; do not erase prior observations.

## Validation before use

Validate each control on supported macOS versions with enabled and disabled
states, multiple users, limited permissions, offline periods and broken
collectors. Compare the results with authoritative OS and vendor interfaces.
OS update compliance requires a maintained policy; an installed security app
or password manager alone does not prove that it is healthy or used.

Test coexistence with existing endpoint agents on an explicitly authorized
device; this prototype makes no compatibility claim. A security or compliance
program must agree on scope, evidence integrity, cadence, exceptions and audit
requirements before treating any output as compliance evidence.

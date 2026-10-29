# Devicegrove

This is an experimental, local-only macOS device security evidence collector
built around fixed osquery queries. It is not an agent, deployment, device
management system or compliance certification. It does not install software,
run automatically, communicate over a network, or persist evidence.

It reports a FileVault `off` observation as a failure signal. FileVault `on`,
screen-lock settings and the OS version remain unknown for compliance purposes
until their coverage and policy can be independently validated. Endpoint
protection and password manager evidence are unknown. See [PRIVACY.md](PRIVACY.md)
for the exact queries and limitations.

Run the synthetic tests with `python3 -m unittest -v`. The tests do not require
osquery and do not establish behaviour on a real Mac. To inspect a consenting
test Mac with an already-installed osquery binary, run
`python3 collector.py /absolute/path/to/osqueryi` as the relevant signed-in user. Check the binary's
provenance and review the output before sharing it. No real-device results are
claimed by this prototype.

Future work includes authenticated enrollment and transport, stale-device
tracking, evidence history and remediation, alongside testing and independent
security and auditor review. No current audit acceptance is claimed.

See [DESIGN.md](DESIGN.md) for the proposed privacy, evidence and security
requirements for that future work.

Devicegrove is open source under the [MIT License](LICENSE).

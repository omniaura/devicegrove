# Collection and privacy

The prototype executes only these fixed queries:

* `SELECT DISTINCT filevault_status FROM disk_encryption;`
* `SELECT enabled, grace_period FROM screenlock;`
* `SELECT version, build FROM os_version;`

It outputs a local UTC timestamp, schema version, status, reason and, where
valid, FileVault `on`, screen-lock password requirement and grace period, and
OS version and build. It never emits raw query errors. It does not query or
emit names, emails, serial numbers, file paths, file contents, credentials,
browser history, network activity, screenshots, keystrokes or app inventory.
The output is written to stdout; anyone with access to that output or a file
it is redirected into may read it. The local timestamp is not trusted time.

Osquery may itself perform local reads or write runtime files. Verify the exact
osquery binary and configuration before any approved device test. Results can
be forged by a compromised local user or binary. Screen-lock data is scoped to
osquery's current logged-in user and does not establish an idle timeout. A
version string alone cannot establish that updates are current. Application
presence cannot establish endpoint protection health or password-manager use.
No coexistence test with other endpoint agents has been performed.

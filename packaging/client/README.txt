AEGIS Linux client

This public package contains the prebuilt client and the components needed to
install, maintain and remove it. It contains no server executable or operator
release tooling. Access configuration is supplied separately and must remain
private. No Rust toolchain, source checkout or GitHub connection is required.

For installation use the accompanying verified bootstrap and the release
sources supplied by your operator. A downloaded public release is not a client
access credential. Keep the private access bundle outside public mirrors.

System prerequisites come from your operating system's trusted repositories.
For an offline installation, prepare those prerequisites and the signed public
release in advance and provide the private access bundle as a local directory.

Private HTTPS bridge (optional, provisioned by your operator)

The native client can use an owned HTTPS/H2 endpoint without Cloudflare. The
endpoint IP still has to be reachable; this does not guarantee passage through
strict IP allowlists. Device inner TLS and enrollment proof remain required.

For an online device, prepare the final identity with `aegis-client device
prepare`, then pin its four-file public bundle with `device bundle-inspect`.
After preparation, your operator supplies owner-only https-bridge.toml in that
identity directory and a separate protected admission-key file. Provision both
before `device redeem` or running the installer: a fresh online installer has
no provisioning pause. The installer resumes the prepared, pinned identity.
Keep the identity and key outside config/runtime purge roots, public bundles
and mirrors. All relay and enrollment outer names must match the bridge
authority. Re-render configuration when changing the private overlay.

Admission bytes and invitation contents must not appear in command arguments
or public profiles. Use protected files; the public profile is not a secret.
The operator archive includes docs/operations/https-bridge.md with the complete
custody, server-role and manual installation procedure. Installed lifecycle,
independent captures and production release acceptance require separate checks.

# credveil

**An inline credential guard for LLM agents that work on network devices.** credveil sits
between a coding agent (Claude Code and similar) and your firewalls, switches and routers, so the
agent can run diagnostics while passwords, keys and certificates stay out of the model's context.

**Design goal: best-effort, low friction.** Minimise what reaches a cloud LLM without getting in
the way of troubleshooting. It is a denylist, so it cannot guarantee that nothing leaks; a
secret that gets through is a bug, and so is a mask that hides diagnostic content. Both are
fixed the same way: a test case first, then the rule.

## How it works

- **The agent never holds a credential.** It addresses devices by alias. credveil reads the
  password or API token from files you created and hands them to `plink`/`ssh`/`curl` through
  files and environment, never command lines.
- **Every byte of output is masked before it is printed.** Vendor packs cover FortiOS,
  keyword-style CLIs (Cisco IOS/NX-OS, Aruba AOS-CX/AOS-S, HPE Comware, Arista, Junos), MikroTik
  RouterOS and generic shells/logs/JSON. Vendor-neutral rules sit on top of them: PEM and PuTTY
  keys, `ENC`, crypt hashes, auth headers, and long hex and base64 blobs. Credential families
  that need no context are masked wherever they appear: JWTs, platform tokens (GitHub, GitLab,
  Slack, Stripe, Google, AWS, OpenAI-style), password hashes (`$argon2…`, `pbkdf2_sha256$…`,
  `$scrypt…`, LDAP `{SSHA}`/`{MD5}`) with the scheme kept, URL-safe (base64url) blobs, and
  credentials in a URL's userinfo.
- **Fail-closed.** If a known credential shows up in the output, or masking throws, nothing is
  printed and credveil exits 90/91. `mask --alias` carries the same rule: a capture is withheld
  rather than printed if one of that device's credentials survives.
- **Diagnostics stay intact.** IP addresses, hostnames, MACs, serials, SPIs and user names pass;
  tests pin that down.
- **Seatbelts for Claude Code:**
  - An always-on guard keeps credential files unread and the inventory unwritten.
  - While the skill is active, a second guard blocks direct `ssh`/`curl` to inventory devices.
  - An output net masks secrets in any tool output.

  These hooks use string matching, not a sandbox: they protect against an agent's mistakes and
  prompt injection, not against a determined adversary.

## Commands

```bash
credveil list                                   # aliases, vendors, which pins/creds are set
credveil run <alias> -c 'get system status'     # SSH: one exec, commands in order
credveil run <alias> --vdom Branch < cmds.txt   # FortiOS: wrapped in config vdom / edit
credveil get <alias> /api/v2/monitor/system/status   # REST GET for vendors with a profile
credveil mask --vendor fortios export.conf > export.masked.conf
credveil mask --alias fw1 capture.log > capture.masked.log  # adds that device's own credentials
credveil audit --vendor aos-cx raw.cfg          # what masking would change: counts and lines only
credveil hostkey <alias>                        # fingerprint to verify and pin
credveil vendors                                # vendor names and which have REST
```

`credveil` is `python3 scripts/credveil.py` from a clone, or the command `pipx install .`
gives you.

## Install

See **[INSTALL.md](INSTALL.md)**. It is written so you can point an agent at this repository
and ask it to wire credveil in.

## Layout

```
credveil/
  config.py            the inventory (one loader for CLI, guard and output net)
  cli.py               commands, fail-closed output
  mask/                engine (blocks → vendor pack → generic rules → known credentials),
                       reusable tokenizers (syntax.py), vendor-neutral rules and the output net
  packs/               one file per system: masking data, CLI context, REST profile
  connectors/          ssh (OpenSSH/plink), https (pinned curl)
  policy.py            guard decisions, harness-neutral
  adapters/            hook protocol per agent runtime (claude_code.py)
hooks/                 hook entry points
tests/                 unit tests and the output-shape corpus (test_corpus.py)
```

Adding a vendor, an API or a shell: [docs/extending.md](docs/extending.md).

## Limits

- The output net cannot rewrite the output of a Bash command that exits non-zero (Claude Code
  limit). Output through `credveil` itself is always masked.
- Live-verified on FortiOS (FortiGate 100F, 7.4.13). The other vendors are verified against
  synthetic output shapes only. Several commands in one SSH exec are verified on FortiOS only.
- REST profiles: FortiOS. Others need a pack with an `ApiProfile`.
- Only Claude Code hooks for now. The guard logic (`policy.py`) and masking are
  harness-neutral, so another runtime needs only an adapter.

## Tests

```bash
python3 -m unittest discover tests
```

No network and no real credentials: devices are faked, secrets in fixtures are planted.

## License

MIT, see [LICENSE](LICENSE).

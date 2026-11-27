# credveil

**An inline credential guard for LLM agents that work on network devices.** credveil sits
between a coding agent (Claude Code and similar) and your firewalls, switches and routers, so the
agent can run diagnostics without passwords, keys or certificates ever reaching the model.

Device output is full of secrets: FortiOS `ENC` blobs, Cisco type 5/8/9 hashes, Junos `$9$`
strings, PSKs, SNMPv3 keys, private keys, live IPsec session keys in `diagnose vpn tunnel list`.
Whatever an agent prints goes to the LLM provider. credveil makes sure what it prints is masked.

## How it works

- **The agent never holds a credential.** It addresses devices by alias. credveil reads the
  password or API token from files you created, and hands them to `plink`/`ssh`/`curl` through
  files and environment, not command lines (`plink -pwfile`, `SSH_ASKPASS`, `curl -H @file`).
- **Every byte of output is masked before it is printed**, by one rule library
  (`scripts/secretmask.py`) with vendor packs for FortiOS, keyword-style CLIs (Cisco IOS/NX-OS,
  Aruba AOS-CX/AOS-S, HPE Comware, Arista, Junos set format) and MikroTik RouterOS, on top of
  vendor-neutral rules (PEM blocks, `ENC`, crypt hashes, long hex and base64 blobs).
- **Fail-closed.** If a known credential shows up in the raw output, or masking throws, nothing
  is printed and credveil exits 90/91.
- **Diagnostics stay intact.** The rules target credentials and certificates. IP addresses,
  prefixes, hostnames, MACs, serials, SPIs and user names pass, because troubleshooting needs
  them; tests pin that down. The broad hex/base64 backstops can still mask a long identifier
  such as a digest.
- **Optional seatbelts for Claude Code**, active only in sessions that invoke the skill:
  - a PreToolUse guard that blocks direct `ssh`/`plink`/`curl`/`Invoke-RestMethod` to an
    inventory device and Bash, PowerShell, Read or Grep access to the credential files;
  - a PostToolUse net that masks unambiguous secrets (private keys, `ENC`, crypt hashes,
    inventory credentials) in any Bash, PowerShell, Read or Grep output.

It is string matching, not a sandbox: it protects against an agent's mistakes, not against a
determined adversary.

## Commands

```bash
credveil list                                   # aliases, vendors, which pins/creds are set
credveil run <alias> -c 'get system status'     # SSH: one exec, commands in order
credveil run <alias> --vdom Branch < cmds.txt    # FortiOS: wrapped in config vdom / edit
credveil get <alias> /api/v2/monitor/system/status   # FortiOS REST, GET only, bearer token
credveil mask --vendor fortios export.conf > export.masked.conf
credveil audit --vendor aos-cx raw.cfg          # what masking would change: counts and line numbers only
credveil hostkey <alias>                         # fingerprint to verify and pin
```

`credveil` here means `python scripts/credveil.py` (`python3` on Linux and macOS).

## Install

Requirements: Python 3.11+ (standard library only), `curl`, and `plink` (PuTTY ≥ 0.75, Windows)
or OpenSSH (Linux/macOS).

```bash
git clone https://github.com/tomasvitha/credveil ~/.claude/skills/credveil   # or clone elsewhere and symlink
mkdir -p ~/.config/credveil/creds
cp ~/.claude/skills/credveil/inventory.example.toml ~/.config/credveil/inventory.toml
```

Then, per device: put the password and/or API token, one value per file, into
`~/.config/credveil/creds/`; add a `[device.<alias>]` block to the inventory; pin the SSH host key
(`credveil hostkey <alias>`, verify it out of band) and the HTTPS public key (`tls_pin`, see
[SKILL.md](SKILL.md) § Setup). `$CREDVEIL_HOME` moves the whole config directory.

As a Claude Code skill, `SKILL.md` tells the agent how to use it, and its frontmatter carries
the two hooks; they start when the skill is invoked. Other agent runtimes can call the CLI
directly; there the wrapper is the only layer.

## Limits

- The output net cannot rewrite the output of a Bash command that exits non-zero (Claude Code
  passes failed calls through PostToolUseFailure, which hooks cannot modify). Output that comes
  through `credveil` itself is always masked.
- REST support is FortiOS only. FortiOS is verified live (FortiGate 100F, FortiOS 7.4.13);
  Cisco IOS, Aruba AOS-CX, HPE Comware, Junos and RouterOS are tested on synthetic fixtures;
  the NX-OS, AOS-S and Arista rules have no fixture yet.
- Pattern rules miss what they have never seen. A secret that got through is a bug: add a
  synthetic fixture to `scripts/test_secretmask.py`, then the rule.
  [docs/false-positives.md](docs/false-positives.md) records the opposite case, over-masking
  and needless blocks.

## Tests

```bash
cd scripts && python -m unittest test_secretmask test_credveil
cd ../hooks && python -m unittest test_hooks
```

No network and no real credentials: devices are faked, secrets in fixtures are planted.

## License

MIT, see [LICENSE](LICENSE).

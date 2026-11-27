---
name: credveil
description: "Masked, credential-free access to network devices (FortiGate, Cisco, Aruba CX/AOS-S, Comware, Junos, MikroTik): `credveil run` (SSH) and `credveil get` (FortiOS REST) read credentials themselves and mask passwords, hashes, keys and certificates before the agent sees any output; `credveil mask`/`audit` do the same for exports and log dumps. Use for any live command on a network device, before reading a raw config export or device log, when setting up device access or credentials, and when the credveil guard blocked a command."
hooks:
  PreToolUse:
    - matcher: "Bash|PowerShell|Read|Grep"
      hooks:
        - type: command
          command: 'bash "$HOME/.claude/skills/credveil/hooks/run-py.sh" credveil_guard.py'
  PostToolUse:
    - matcher: "Bash|PowerShell|Read|Grep"
      hooks:
        - type: command
          command: 'bash "$HOME/.claude/skills/credveil/hooks/run-py.sh" credveil_outnet.py'
---

# credveil — device access without secrets in the session

Network-device output carries secrets: `ENC` blobs, password hashes, PSKs, private keys,
SNMP communities, live IPsec session keys (`diagnose vpn tunnel list`). Anything an agent
prints goes to the LLM provider. credveil sits between the agent and the device:

- **Credentials never enter the session.** credveil reads the password/token files named in the
  inventory and hands them to plink/ssh/curl through files (`-pwfile`, askpass, `-H @file`), not
  argv. The agent works with an alias.
- **Output is masked before it is printed** by `scripts/secretmask.py`, the single source of
  the secret rules (other tools may import it).
- **Fail-closed:** if a known credential appears in the device output, or masking crashes,
  credveil prints nothing and exits 90/91. Report it as a secretmask bug, never route around it.

Two hooks back this up. They are **skill-scoped** (this file's frontmatter): they start when
credveil is invoked and run to the end of that session, and are absent from every other session.
credveil is opt-in; it does not police what goes into your own repositories.

| Hook | Does | Limits |
|---|---|---|
| `hooks/credveil_guard.py` (PreToolUse: Bash, PowerShell, Read, Grep) | blocks ssh/plink/curl/… **in command position** to an inventory host, and any Bash, PowerShell, Read or Grep reference to a credential path (Glob, Edit, Write and MCP tools are not covered); prose, quoted text, heredoc bodies and commit messages naming a device pass | string matching: a seatbelt, not a sandbox |
| `hooks/credveil_outnet.py` (PostToolUse: Bash, PowerShell, Read, Grep) | masks unambiguous secrets (private keys, `ENC`, crypt/`$9$` hashes, `key=N <hex>`, inventory credentials) in **any** tool output | Claude Code only; **output of a command exiting non-zero is not covered** (PostToolUseFailure cannot be rewritten); skips files inside this skill |

Other agent runtimes get neither hook: there the wrapper is the only layer, so use it.

**A Read that came back with `<masked…>` markers is not the file on disk.** Change such a file
with Edit only (its exact match fails safely on a masked span); a Write built from the masked
view would store `<masked>` into the real file.

## Running it

```bash
N=~/.claude/skills/credveil/scripts/credveil.py      # Windows: python $N …   Linux: python3 $N …
python $N list                                # aliases, vendors, which pins/creds are set
python $N run <alias> -c 'get system status' -c 'get router info ospf neighbor'
python $N run <alias> --vdom Branch <<'EOF'
get router info ospf neighbor
diagnose vpn tunnel list name S2S-HQ
EOF
python $N run <alias> --global -c 'get system ha status'
python $N get <alias> /api/v2/monitor/router/ipv4 --vdom Branch -p filter=type==ospf
```

- One `run` is one SSH exec: all commands, in order, in one stateless CLI session. FortiOS
  `--vdom`/`--global` wrap them in `config vdom/edit … end` for you.
- `get` is GET only, FortiOS bearer token only, paths under `/api/v2/{monitor,cmdb,log}/`;
  query parameters go through `--vdom` and `-p k=v`. JSON bodies are masked by key and value.
- stderr ends with `credveil: masked <category>=<count>…`: what was removed. Masked values read
  `<masked>`, `<masked:b64>`, `<masked:known>`, `<masked:private-key>`,
  `<masked:unterminated-…>`, `<hex:N>`, `<pem:certificate sha=…>`, `<hexdump:N lines>`.
- Output is LF on every OS; `mask` writes the input file's own line ending, so `diff raw
  masked` shows only what masking changed. Git Bash's rewrite of `/api/v2/…` to
  `C:/Program Files/Git/api/v2/…` is undone by `get` itself.
- credveil does not decide which commands are safe to send: device-side safety (read-only vs.
  change) stays with the operator's own rules.

### Files: exports and log dumps

```bash
python $N mask --vendor fortios export.conf > export.masked.conf   # then read the masked copy
python $N audit --vendor aos-cx raw1.cfg raw2.cfg                  # counts + line numbers only
```

`audit` is safe to run on a raw capture: it prints no values. Use it to check what masking does
to a real capture before a pattern becomes a test case.

**Scope: credentials and certificates only.** IP addresses, prefixes, hostnames, MACs, serials,
SPIs and user or group names stay in the output: troubleshooting needs them. A new rule that would
touch them fails `test_addressing_never_masked` or the `Identity` tests. The broad backstops
(hex runs of 32+, mixed base64 runs of 40+) can still mask a long identifier outside an identity
field, such as a digest or a git SHA; log such a case in `docs/false-positives.md`. Pseudonymizing them is a
separate job for material that leaves to third parties.

## Setup (operator, once per machine / device)

1. `mkdir -p ~/.config/credveil/creds`; copy `inventory.example.toml` to
   `~/.config/credveil/inventory.toml` (or `$CREDVEIL_HOME/inventory.toml`) and fill in a
   `[device.<alias>]` per box.
2. Credentials: one value per file in `~/.config/credveil/creds/` (the agent is blocked from
   that directory). Keep the source of truth in a password manager.
3. Host key: `python $N hostkey <alias>` prints the fingerprint; verify it, then set `hostkey`
   (plink, Windows) or append `ssh-keyscan` output to `~/.config/credveil/known_hosts` (Linux).
   REST: `tls_pin` is the SPKI hash (`sha256//…`): `openssl s_client -connect <host>:443 |
   openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary
   | base64`.
4. Legacy credential files elsewhere go into `[guard] protect`; FQDNs/HA peers into
   `[guard] hosts`.

Exit codes: device/curl's own, or 90 withheld (credential in output), 91 withheld (masking
failed), 92 inventory/usage, 93 transport (plink/ssh/curl missing, timeout).

## Extending the rules

**Over-masking or a guard block on a harmless command → append it to
[`docs/false-positives.md`](docs/false-positives.md)** (layer, synthetic example, cost, fix idea)
and carry on; that file is the queue for the next tuning pass.

A secret that got through is a bug in `scripts/secretmask.py`: add the vendor form as a
synthetic fixture to `scripts/test_secretmask.py` (planted value in the SECRETS list, the
diagnostic context around it in KEEP), then the rule. Rule layers: `generic` (every vendor),
`fortios`, `cli` (keyword-then-value CLIs), `routeros`; `net_mask` is the high-precision
subset the output net applies to arbitrary text, so it stays free of keyword rules.

Done when every suite is green, run as its own command:

```bash
cd ~/.claude/skills/credveil/scripts && python -m unittest test_secretmask test_credveil
cd ../hooks && python -m unittest test_hooks
```

## Status

Tested on synthetic fixtures and fake devices; hooks verified end to end in headless Claude Code
runs (masking of Bash, PowerShell, Read, Grep output; direct ssh and credential reads blocked;
skill-scoped hooks inactive until the skill is invoked). curl `-k --pinnedpubkey` under Windows
Schannel enforces the pin. **Live on a FortiGate 100F (FortiOS 7.4.13)**: plink
`-m`/`-pwfile`/`-hostkey`, `--global` and `--vdom`, IPsec session keys masked in a real
`diagnose vpn tunnel list` with SPIs intact, REST `get` with a pinned cert and bearer token, and
FortiAnalyzer logs read through the FortiGate API. Synthetic fixtures cover Cisco IOS, Aruba
AOS-CX, HPE Comware, Junos and RouterOS; NX-OS, AOS-S and Arista rules exist without a fixture yet. REST
is FortiOS-only (Aruba CX REST needs a session login, not built).

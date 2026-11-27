---
name: credveil
description: "Masked, credential-free access to network devices (FortiGate, Cisco, Aruba CX/AOS-S, Comware, Junos, MikroTik): `credveil run` (SSH) and `credveil get` (REST) read credentials themselves and mask passwords, hashes, keys and certificates before the agent sees any output; `credveil mask`/`audit` do the same for exports and log dumps. Use for any live command on a network device, before reading a raw config export or device log, when setting up device access or credentials, and when the credveil guard blocked a command."
hooks:
  PreToolUse:
    - matcher: "Bash|PowerShell|Read|Grep|Edit|Write|MultiEdit|NotebookEdit"
      hooks:
        - type: command
          command: 'bash "${CLAUDE_PLUGIN_ROOT:-$HOME/.claude/skills/credveil}/hooks/run-py.sh" pre full'
  PostToolUse:
    - matcher: "Bash|PowerShell|Read|Grep"
      hooks:
        - type: command
          command: 'bash "${CLAUDE_PLUGIN_ROOT:-$HOME/.claude/skills/credveil}/hooks/run-py.sh" post'
---

# credveil — device access without secrets in the session

Device output carries secrets: `ENC` blobs, password hashes, PSKs, private keys, SNMP
communities, live IPsec session keys. Anything you print goes to the LLM provider. credveil sits
between you and the device:

- **You never hold a credential.** credveil reads the password/token files named in the
  inventory and hands them to plink/ssh/curl through files, not argv. You work with an alias.
- **Output is masked before it is printed.** Fail-closed: if a known credential appears in the
  output, or masking crashes, credveil prints nothing and exits 90/91. Report it, never route
  around it.
- **Goal: best-effort, low friction.** Fewer secrets reaching the model, without getting in the
  way of troubleshooting. Over-masking and needless blocks count as bugs too.

## Running it

```bash
N="${CLAUDE_SKILL_DIR}/scripts/credveil.py"    # Windows: python "$N" …   Linux/macOS: python3 "$N" …
python3 "$N" list                              # aliases, vendors, which pins/creds are set
python3 "$N" run <alias> -c 'get system status' -c 'get router info ospf neighbor'
python3 "$N" run <alias> --vdom Branch <<'EOF'
get router info ospf neighbor
diagnose vpn tunnel list name S2S-HQ
EOF
python3 "$N" run <alias> --global -c 'get system ha status'
python3 "$N" get <alias> /api/v2/monitor/router/ipv4 --vdom Branch -p filter=type==ospf
python3 "$N" mask --vendor fortios export.conf > export.masked.conf   # then read the masked copy
python3 "$N" audit --vendor aos-cx raw1.cfg raw2.cfg                   # counts + line numbers only
python3 "$N" vendors                                                   # vendor names it knows
```

- One `run` is one SSH exec: all commands, in order, in one CLI session. Verified line by line
  on FortiOS; other CLIs may take one command per exec, so send one `-c` per `run` there.
  Turn paging off on the device side if output arrives cut by `--More--`.
- `--vdom`/`--global` exist where the vendor pack defines a context (FortiOS).
- `get` is GET only, for vendors with a REST profile (`credveil vendors` marks them).
- stderr ends with `credveil: masked <category>=<count>…`. Masked values read `<masked>`,
  `<masked:b64>`, `<masked:known>`, `<masked:private-key>`, `<hex:N>`,
  `<pem:certificate sha=…>`, `<hexdump:N lines>`.
- credveil does not decide which commands are safe to send: read-only vs. change stays with the
  operator's rules.

**Scope: credentials and certificates only.** IPs, hostnames, MACs, serials, SPIs, user and
group names stay: troubleshooting needs them.

## The hooks

| Hook | When | Does |
|---|---|---|
| `pre home` | always (wired in user settings, see INSTALL.md) | blocks reads of credential files, writes into `$CREDVEIL_HOME`, setting `CREDVEIL_HOME` |
| `pre full` | from this skill's invocation on | also blocks ssh/plink/curl/… **in command position** to an inventory host |
| `post` | from this skill's invocation on | masks unambiguous secrets in Bash/PowerShell/Read/Grep output; a config export with a known header gets its full vendor pack |

String matching, a seatbelt not a sandbox. The output of a Bash command that exits non-zero
is not rewritten (Claude Code limit). **A Read that shows `<masked…>` is not the file on disk:**
change such a file with Edit only; a Write built from the masked view would store `<masked>`.

## When something is wrong

- A secret got through, or masking ate diagnostic content → add a case to
  `tests/test_corpus.py` (synthetic value, the real output shape), then fix the vendor pack
  in `credveil/packs/`. Not fixable now → log it in `docs/false-positives.md` and carry on.
- A new system (another vendor, an API, a shell) → one new file in `credveil/packs/`; see
  `docs/extending.md`.

Done when every suite is green, run as its own command: `python3 -m unittest discover tests`
from the skill directory.

Setup and wiring for a new machine or device: `INSTALL.md`.

# credveil — observed friction and misses

The queue for the next tuning pass. Friction counts as a bug: over-masking hides diagnostics,
and a needless block costs a call. Append an entry when you see one live. Name the layer, give
a **synthetic** example (never the real value), say what it cost and how it might be fixed. When
a corpus case and a rule close the entry, move it to *Closed* as one line.

Layers: `pack <name>` or `generic` (masking), `guard home|full` (PreToolUse), `outnet`
(PostToolUse), `cli` (tooling friction).

## Open

### `generic` — FortiOS session `hash=` masked as `<hex:32>`
- Seen in `diagnose sys session list`: `hash=0123…` (32 hex) becomes `<hex:32>`.
- Cost: low. It is a session-table hash and seldom needed.
- Fix idea: a FortiOS-pack exemption for `hash=` inside session-list lines. It is not added to
  the generic exemptions, because `hash` can also label a password hash elsewhere.

### `ssh` — `--More--` paging could split a value (unverified)
- If the device pages output, a secret split around `--More--` is masked only up to the split.
- Fix idea: disable paging per pack (`terminal length 0`, `config system console / set output
  standard`) via `wrap_commands`. Check first whether plink `-m` allocates a pty.

## Closed

- `generic` — a 32-hex SAML user id in `xauthuser` no longer masks; identity keys skip the
  backstops (`test_mask.Identity`).
- `guard full` — a device name with "SSH" in a commit message no longer blocks; transports
  count only in command position (`test_claude_code.Guard`).
- `cli` — Git Bash's `/api/v2/…` path rewrite is undone by `get` itself (`test_cli`).
- `cli` — `mask` keeps the input's line endings, so `diff raw masked` stays clean (`test_cli`).
- `pack cli` — description lines, certificate serials and fingerprints, git SHAs and key
  lengths pass unchanged (`test_corpus.UNCHANGED`).

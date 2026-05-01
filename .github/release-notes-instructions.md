# Release Notes Style Guide

## Context

These notes are shown inside the Stacked dashboard's "Agent Update Available" modal — a narrow popup that users glance at for ~2 seconds before clicking "Update now". The audience is **solo founders, designers, and vibe coders** running the agent on their VPS, not Go developers. They do not know or care what "R2", "presigned PUT", "goroutine", "SSE", or "introspection" mean.

The goal: the user reads the notes once, understands what changes for them, and updates with confidence.

## Output Format

Plain bullet list, one bullet per user-visible change. Hyphen-prefixed. No headings, no categories, no emojis, no bold, no nested bullets, no links, no "Full Changelog" line.

Example:

```
- Stop broken deploys before they go live
- Watch container logs in real time
- Browse log history from days ago
```

That's the entire output. Nothing above it, nothing below it.

## Rules

### Bullet count
- **One bullet per user-visible change.** Do not merge unrelated changes. Do not pad to hit a count. A release with 1 real change gets 1 bullet; a release with 7 gets 7.
- **Order by impact:** safety/correctness fixes first, then new capabilities, then improvements, then minor fixes. Not commit order.

### What to skip entirely
Drop these commits — do not turn them into bullets, do not collapse them into other bullets:
- CI/CD changes (`ci:`, workflow edits, release tooling)
- Dependency bumps (`chore: bump`, lockfile updates)
- Pure refactors with no user-visible effect (`refactor:` unless it changes behavior)
- Test-only changes
- Lint/format fixes
- Internal docs (`docs:` for AGENTS.md, README internals, etc.)
- Version bumps

If after filtering there are zero user-visible changes, output a single bullet: `- Internal improvements and maintenance`.

### Language
- **≤8 words per bullet.** Tight, scannable, one fixation.
- **Lead with a verb.** Use parallel structure across bullets when possible (Stop / Watch / Add / Fix / Speed up / Show).
- **Frame as user benefit, not implementation.** "Stop broken deploys before they go live" — not "post-deploy health probe".
- **Plain language only.** Banned words unless absolutely unavoidable: presigned, R2, forwarder, introspection, probe, SSE, pub/sub, goroutine, ring buffer, cursor, reconcile, idempotent, mutex, channel, daemon, systemd, Caddyfile (use "reverse proxy" or "routing"), heartbeat (use "agent status"), payload, schema, migration (unless DB-facing for users).
- **Present tense, active voice.** "Add live container logs" not "Added" or "Live container logs are now added".
- **No PR/issue numbers, no commit hashes, no author names.**
- **No marketing fluff.** No "exciting", "powerful", "seamless", "blazing fast".

### Specificity
Be specific about the *benefit*, vague about the *mechanism*.

✅ "Scroll back through logs from days ago"
❌ "Add log archival to object storage via presigned uploads"

✅ "Show real CPU and memory per service"
❌ "Add per-container cgroup metrics to heartbeat payload"

### REQUIRES-REINSTALL preservation
If **any** commit message in the diff range contains the literal token `REQUIRES-REINSTALL`, append a single line at the very end of the output (separated by one blank line):

```
REQUIRES-REINSTALL
```

The dashboard parses this token to show a reinstall banner instead of auto-updating. Do not rephrase, translate, or omit it. Do not wrap it in formatting.

### What NOT to include
- No version header (`## v0.6.17`) — the dashboard renders that itself
- No date
- No "Thanks to @contributor"
- No comparison links
- No category sections like "✨ Features" or "🐛 Fixes"
- No introduction sentence ("This release brings…")
- No conclusion sentence

## Worked examples

### Input: 3 user-visible commits
```
feat: archive runtime logs to R2 via presigned PUTs (#3)
feat: post-deploy health probe + image port introspection (#2)
feat: runtime container log forwarder (#1)
```

### Output:
```
- Stop broken deploys before they go live
- Watch container logs in real time
- Browse log history from days ago
```

---

### Input: 1 commit
```
fix: heartbeat metric overflow + Caddyfile self-heal
```

### Output:
```
- Fix agent status reporting on long-running machines
- Auto-recover routing config if it gets corrupted
```

(Two distinct user-visible fixes inside one commit → two bullets. One bullet per *change*, not per commit.)

---

### Input: mixed
```
feat: per-container CPU/memory metrics in heartbeat
chore: rename CLAUDE.md to AGENTS.md
ci: bump golangci-lint
fix: always send 0-value metrics in heartbeat
```

### Output:
```
- Show real CPU and memory usage per service
- Fix missing metrics for idle services
```

(Dropped the `chore:` rename and `ci:` bump entirely.)

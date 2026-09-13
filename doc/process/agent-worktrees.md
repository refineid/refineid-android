# Agent Worktrees

Status: Active

Date: 2026-09-12

## Context

Several agents (and the owner) work on this repository at the same time.
One task, one worktree, one branch, one pull request keeps that work from
colliding and keeps the main checkout pristine for integration.

## Topology and naming

- The main checkout is never edited directly. It integrates and releases.
- Each task gets a worktree under `~/src/wt/`, never under `/tmp` or directly in `~/src/`:
  `~/src/wt/refineid-android-<topic>` on branch `agent/<topic>`.
- One branch carries one pull request. Never stack unrelated work onto a
  branch that already has an open pull request.

## Starting a task

1. Update local main: `git checkout main && git pull --ff-only`.
2. Create the worktree: `git worktree add ~/src/wt/refineid-android-<topic> -b agent/<topic>`.
3. Copy `local.properties` into the worktree (machine-global SDK path).
   Never copy signing secrets (`keystore.properties`, service accounts):
   worktrees build debug only, release signing stays in the main checkout.
4. Write `WHATSUP.md` in the worktree root (see below).
5. Run `Scripts/agent-housekeeping.sh` and act on what it reports.

Gradle and Cargo dependency caches live outside the checkout, and the
Gradle build cache is enabled, so a fresh worktree downloads nothing and
reuses compiled output. Only the Rust crates recompile from scratch.

## WHATSUP.md

Every worktree carries a `WHATSUP.md` work log in its root: plain Markdown
so owners and agents can both read it. It records why the worktree was
born, where the work stopped, and whether it is worth resuming. Work gets
diverted to another focus at random; that is normal, and the log is what
makes a diverted worktree evaluable later instead of mysterious.

```markdown
# WHATSUP

branch: agent/satellite-icon
purpose: Replace the Etakaytto Share icon with satellite_alt.
started: 2026-09-12T11:05+03:00 by ivory-emission (Muse)
heartbeat: 2026-09-12T11:20+03:00
status: paused-diverted (pulled onto release signing; resume by rebuilding)
```

Fields (each value stays on its own single line so tooling can read it):

- `purpose`: why this worktree exists, one or two sentences on one line.
- `started`: timestamp and owner (session name plus human or agent).
- `heartbeat`: last time the owner touched the work; refresh it when
  starting, pausing, or finishing.
- `status`: `in-progress`, `paused-diverted` (with a note saying what
  diverted it and how to resume), or `done-pending-merge`.

## Housekeeping

`Scripts/agent-housekeeping.sh` reports every worktree with its branch,
merge state, dirty files, unpushed commits, claim freshness, and disk use.
With `--clean` it removes only what is provably done:

- The branch is merged into main, the tree is clean, and nothing is
  unpushed. The work is fully preserved in main, so deleting the worktree
  loses nothing. The branch goes with it.

Everything else is reported, never destroyed, with the `WHATSUP.md`
purpose and status quoted so the evaluator — owner or agent — can decide
in seconds whether to resume work or clean up. In particular:

- A fresh claim is hands off, unconditionally.
- Uncommitted changes or unpushed commits are never auto-deleted.

## Finishing a task

1. Run the quality gates (`./gradlew check`) in the worktree.
2. Commit on the task branch (subject and body only) and push.
3. Open one pull request for the branch.
4. Conduct iterative code review via Muse (`discuss-with-muse start --pr <NUM>`).
   Muse runs with `--model muse-spark-1.3-contributor --reasoning-effort max`.
   Codex reviews (`codex --model gpt-6-astra -c model_reasoning_effort=high`)
   are reserved strictly for explicit maintainer requests.
5. Squash-merge once CI and reviews are green, so the `main` history stays
   linear. The pull request preserves the branch history.
6. Remove the worktree (`git worktree remove`), delete the branch, and
   fast-forward local main.

## Out of scope

The development phone is owner-coordinated. Agents do not arbitrate,
reserve, or toggle its transports; if the USB transport drops, the WiFi
transport carries the install.

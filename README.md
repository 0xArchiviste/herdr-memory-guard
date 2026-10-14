# Herdr Memory Guard

A small Linux / WSL plugin that reclaims memory held by long-idle Herdr agent threads before they exhaust the machine. Python 3.11+, no pip dependencies. Requires Herdr 0.9.3 or newer and Linux pidfds. Automatic startup uses a systemd user service.

## Install

```sh
herdr plugin install 0xArchiviste/herdr-memory-guard --yes
herdr plugin action invoke start --plugin 0xarchiviste.herdr-memory-guard
herdr plugin action invoke status --plugin 0xarchiviste.herdr-memory-guard
# After reviewing the dry-run status:
herdr plugin action invoke enable --plugin 0xarchiviste.herdr-memory-guard
```

Installation starts in observation mode. Enabling automatic reclamation is persistent. The startup hook starts the monitor after Herdr restores its session. A running server does not invoke newly installed startup hooks, so use the explicit `start` action above.

## What it does

* Samples Linux `MemAvailable`, memory pressure stalls, and, on WSL, Windows available physical memory. Swap use is reported, but old swap alone does not mean the machine is under current pressure.
* Tracks idle agent process-tree RSS plus swap. This is an approximate budget: shared pages can be counted more than once. Quiet observations use actual terminal content and agent state sequences; routine Herdr metadata revisions do not count as agent activity.
* Hibernates a supported agent after two hours idle, or 30 minutes when memory is under pressure or eligible idle agents exceed a 2 GiB budget. Every action also requires three minutes of continuously observed quiet output and low CPU activity. Herdr Projects timestamps can establish age; they never substitute for live quiet observation.
* Writes a private, durable checkpoint with the native session ID, working directory, thread record, recent terminal output, and process identities before doing anything.
* Sends SIGTERM to the verified foreground agent and its captured descendants, allowing the agent time to flush session data. It keeps the shell, pane, worktree, branches, files, and Herdr Projects records. It never sends SIGKILL, kills a process group, or kills the Herdr server. Survivors are reported as partial reclamation.
* Closes an empty shell pane only when its matching local Herdr Projects record is already resolved, it is at least a day old, and it has no background descendants. The checkpoint retains recent scrollback; the worktree is untouched.

Default scope is **local Herdr Projects worker threads**. Coordinators, focused panes, working/blocked/unknown agents, pending launches, unrecognized process trees, unsupported session types, and pinned panes/projects are protected. Claude, Codex, and OpenCode have native session-resume adapters. There is no automatic interruption of active work, even under severe pressure.

Each cycle rechecks agent state, foreground ownership, project state, process identity, and focus before signaling. Linux pidfds prevent a recycled PID from receiving a signal. Herdr does not offer an atomic compare-and-hibernate API: a very small race remains between the last state check and termination. Explicitly pin panes that must stay resident. The native session ID is preserved, but unsent application input is not guaranteed to survive a native restart.

## Resume and control

In a hibernated pane, invoke **Memory Guard: resume this hibernated agent** from Herdr's plugin actions. It starts the native CLI with the saved session ID in the existing pane. It does not send an agent prompt. The CLI also supports:

```sh
python3 /path/to/guard.py resume --pane w1:p2
python3 /path/to/guard.py protect --pane w1:p2
python3 /path/to/guard.py unprotect --pane w1:p2
python3 /path/to/guard.py once          # dry run; never signals
python3 /path/to/guard.py once --apply  # also requires enabled=true
```

Use the same `--socket`, `--config-dir`, and `--state-dir` as the installed service when running commands outside a plugin action. Their defaults target the default Herdr session. A replaced server or pane requires manual native resume using the checkpoint's `resume_args` in its saved working directory. Resume restores the native conversation; it does not replay arbitrary launch flags or grant new permissions.

```sh
herdr plugin action invoke pause --plugin 0xarchiviste.herdr-memory-guard
herdr plugin action invoke stop --plugin 0xarchiviste.herdr-memory-guard
```

`pause` leaves observation running. `stop` disables the session's systemd service; the Herdr startup hook will start it again on the next server start. To uninstall, stop first, then run `herdr plugin uninstall 0xarchiviste.herdr-memory-guard`. A disabled/uninstalled plugin causes the monitor to exit at its next poll. A systemd service is named `herdr-memory-guard-<socket-hash>.service`; inspect it with `systemctl --user status` or `journalctl --user -u`.

## Configuration and privacy

Edit `config.json` in the directory printed by:

```sh
herdr plugin config-dir 0xarchiviste.herdr-memory-guard
```

Only override settings you want to change; defaults are in `guard.py:DEFAULTS`. The `enable` action writes all defaults for convenience. Useful settings include `idle_seconds`, `pressure_idle_seconds`, `idle_budget_mib`, `max_actions_per_cycle`, `protected_panes`, and `protected_projects`. Unknown or malformed settings stop automatic actions. Setting `managed_threads_only` to false also admits supported idle agents outside Projects, but coordinator protection remains on by default.

Linux pressure starts below 20% available memory and clears above 25%; Windows pressure starts below 15% and clears above 20%. Three actions are permitted per cycle. An idle process tree must stay below 2% of one CPU during quiet observation. The monitor itself is limited by systemd to 128 MiB and 10% of one CPU, with a 30-second polling interval. Windows memory is sampled every two minutes. Process and checkpoint state are isolated by socket and server identity; server restart resets quiet observations.

State is stored in `HERDR_PLUGIN_STATE_DIR` when invoked through Herdr, otherwise `~/.local/state/herdr-memory-guard`. Each socket has a separate directory containing `status.json`, `state.json`, a bounded audit log, and `checkpoints/`. These files can contain private paths, terminal output, and session IDs. Directories are private and checkpoint files are mode 0600. They are never uploaded. The plugin makes no network requests.

Checkpoint storage is bounded at 256 MiB / 1,000 checkpoints. When the limit is reached, cleanup stops with an error; recovery history is never silently deleted. Archive checkpoints yourself if you want to free that budget. Existing data and git worktrees are never deleted by this plugin.

## Development

```sh
python3 -m unittest discover -s tests -v
herdr plugin link /absolute/path/to/herdr-memory-guard --disabled
```

Tests cover unsafe agent states, coordinators, focus changes, session identity, process boundaries, PID reuse, activity resets, checkpoint failure, storage limits, dry runs, resolved-shell jobs, and real SIGTERM cleanup of a disposable subprocess tree.

See [Herdr plugins](https://herdr.dev/docs/plugins/) and [Herdr socket API](https://herdr.dev/docs/socket-api/). This is an independent community plugin, not an official Herdr component.

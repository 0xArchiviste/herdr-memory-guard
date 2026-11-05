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

* Acts **only under genuine memory pressure**: Linux `MemAvailable`, Linux memory stalls (PSI), or, on WSL, Windows available physical memory. Idle agents holding memory is not pressure; with headroom nothing is hibernated, however long an agent has been idle. Swap use is reported, but old swap alone does not mean the machine is under current pressure.
* Every decision carries a human-readable reason naming the threshold and the numbers, for example `memory pressure: Linux MemAvailable 9.8% (9210 MiB) is below 20%; agent idle 2h05m, quiet 3m; frees ~850 MiB`. The reason is stored in the status file, the audit log, the checkpoint, and the journal.
* Under pressure, hibernates a supported agent that has been idle for 30 minutes and quiet (no terminal output, agent state change, or CPU above 2% of one CPU) for three minutes of continuous observation.
* Never stops an agent that is:
  * a project coordinator (protected by default);
  * on a thread that is waiting on the user: Herdr Projects groups *waiting on you*, *ready for review* and *landing*, an unacknowledged report, an open pull request, an open question or permission prompt, or an agent that reported it is waiting;
  * on a thread that is working, or that worked within the last hour (`recent_work_seconds`);
  * focused, pinned, unmanaged, or without a verifiable native session ID.

  Thread state comes from `herdr-projects thread list <project> --json`, rechecked just before acting. If it cannot be read, the thread is protected.
* Writes a private, durable checkpoint with the reason, native session ID, exact resume command, working directory, thread record, recent terminal output, and process identities before doing anything.
* Sends SIGTERM to the verified foreground agent and its captured descendants, allowing the agent time to flush session data. It keeps the shell, pane, worktree, branches, files, and Herdr Projects records. It never sends SIGKILL, kills a process group, or kills the Herdr server. Survivors are reported as partial reclamation.
* Closes an empty shell pane only when its matching local Herdr Projects record is already resolved, it is at least a day old, and it has no background descendants (`close_resolved_shells`). The checkpoint retains recent scrollback; the worktree is untouched.

### No retry loops

A failed action is not retried every cycle. Transient failures back off exponentially (5 minutes, doubling, up to a day). A refusal that retrying cannot fix, such as Herdr's `confirmation_required` when closing a pane would close a worktree group, stops attempts on that pane until its occupant, agent state, or thread state changes. A failed attempt reuses its checkpoint instead of writing a new one each cycle, and the monitor removes superseded duplicate checkpoints of attempts that changed nothing when it starts (`guard.py prune-checkpoints` previews this; add `--apply` to run it). Successful hibernation records are never pruned.

### Coordinators keep context

After a hibernation, a pane close, or a resume, the guard leaves an item in that project's Herdr Projects inbox (`kind = "memory-guard"`) with the thread ID, the reason, the checkpoint path, the exact `guard.py resume` command, and the native fallback (for example `cd <worktree> && claude --resume <session>`). The Herdr Projects ticker announces new inbox items only to an idle coordinator with an empty input box, so the guard never types into a busy agent. Set `notify_coordinators` to false to turn this off.

Currently hibernated panes are listed in `hibernated.json` next to `status.json`, with project, thread, agent, session ID, reason, checkpoint, and both resume commands. Dashboards can read it; an entry disappears once the pane runs an agent again.

Default scope is **local Herdr Projects worker threads**. Claude, Codex, and OpenCode have native session-resume adapters. There is no automatic interruption of active work, even under severe pressure.

Each cycle rechecks agent state, foreground ownership, project state, process identity, and focus before signaling. Linux pidfds prevent a recycled PID from receiving a signal. Herdr does not offer an atomic compare-and-hibernate API: a very small race remains between the last state check and termination. Explicitly pin panes that must stay resident. The native session ID is preserved, but unsent application input is not guaranteed to survive a native restart.

## Resume and control

In a hibernated pane, invoke **Memory Guard: resume this hibernated agent** from Herdr's plugin actions. It starts the native CLI with the saved session ID in the existing pane (`claude --resume <id>`, `codex resume <id>`, `opencode --session <id>`), then checks that Herdr reports the agent on that same session and says whether it was verified. It does not send an agent prompt. The CLI also supports:

```sh
python3 /path/to/guard.py resume --pane w1:p2
python3 /path/to/guard.py protect --pane w1:p2
python3 /path/to/guard.py unprotect --pane w1:p2
python3 /path/to/guard.py once          # dry run: decision and reason for every pane; never signals
python3 /path/to/guard.py once --json   # the same as the full JSON report
python3 /path/to/guard.py once --apply  # also requires enabled=true
python3 /path/to/guard.py prune-checkpoints [--apply]
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

Only override settings you want to change; defaults are in `guard.py:DEFAULTS`. The `enable` action writes all defaults for convenience. Useful settings include `pressure_idle_seconds`, `recent_work_seconds`, `max_actions_per_cycle`, `protected_panes`, `protected_projects`, `failure_backoff_seconds`, `notify_coordinators`, and `herdr_projects_bin`. Unknown or malformed settings stop automatic actions. The old `idle_seconds` and `idle_budget_mib` settings are accepted but ignored (the dry run lists them), because idle time and idle memory alone are no longer reasons to act. Setting `managed_threads_only` to false also admits supported idle agents outside Projects, but coordinator protection remains on by default.

Linux pressure starts below 20% available memory and clears above 25%; Windows pressure starts below 15% and clears above 20%. Three actions are permitted per cycle, and only while pressure lasts. An idle process tree must stay below 2% of one CPU during quiet observation. The monitor itself is limited by systemd to 128 MiB and 10% of one CPU, with a 30-second polling interval. Windows memory is sampled every two minutes. Process and checkpoint state are isolated by socket and server identity; server restart resets quiet observations.

State is stored in `HERDR_PLUGIN_STATE_DIR` when invoked through Herdr, otherwise `~/.local/state/herdr-memory-guard`. Each socket has a separate directory containing `status.json`, `state.json`, `hibernated.json`, a bounded audit log, and `checkpoints/`. These files can contain private paths, terminal output, and session IDs. Directories are private and checkpoint files are mode 0600. They are never uploaded. The plugin makes no network requests. Coordinator notifications are files in the local Herdr Projects folder.

Checkpoint storage is bounded at 256 MiB / 1,000 checkpoints. When the limit is reached, cleanup stops with an error; recovery history is never silently deleted. Archive checkpoints yourself if you want to free that budget. Existing data and git worktrees are never deleted by this plugin.

## Development

```sh
python3 -m unittest discover -s tests -v
herdr plugin link /absolute/path/to/herdr-memory-guard --disabled
```

Tests cover pressure versus headroom, threads waiting on the user, recent work, failure backoff, checkpoint reuse and pruning, coordinator inbox notifications, session resume arguments and verification, per-pane dry-run reasons, unsafe agent states, coordinators, focus changes, session identity, process boundaries, PID reuse, activity resets, checkpoint failure, storage limits, dry runs, resolved-shell jobs, and real SIGTERM cleanup of a disposable subprocess tree.

See [Herdr plugins](https://herdr.dev/docs/plugins/) and [Herdr socket API](https://herdr.dev/docs/socket-api/). This is an independent community plugin, not an official Herdr component.

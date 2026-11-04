#!/usr/bin/env python3
"""Herdr memory guard. Python 3.11+, Linux pidfds, no third-party packages."""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import tomllib
from collections import Counter

PLUGIN = "0xarchiviste.herdr-memory-guard"
MIB = 1024 * 1024
SAFE_STATES = {"idle", "done"}
SHELLS = {"bash", "zsh", "fish", "sh", "dash"}
DEFAULTS = {
    "enabled": False,
    "interval_seconds": 30,
    "pressure_idle_seconds": 1800,
    "recent_work_seconds": 3600,
    "quiet_seconds": 180,
    "resolved_shell_seconds": 86400,
    "max_actions_per_cycle": 3,
    "min_reclaim_mib": 64,
    "available_percent": 20,
    "recovery_percent": 25,
    "host_available_percent": 15,
    "host_recovery_percent": 20,
    "psi_some_avg10": 10,
    "max_cpu_percent": 2,
    "projects_root": "~/.herdr-projects",
    "managed_threads_only": True,
    "protect_coordinators": True,
    "protected_panes": [],
    "protected_projects": [],
    "checkpoint_limit_mib": 256,
    "max_checkpoints": 1000,
    "sample_windows_host": True,
    "close_resolved_shells": True,
    "failure_backoff_seconds": 300,
    "failure_backoff_max_seconds": 86400,
    "notify_coordinators": True,
    "herdr_projects_bin": "herdr-projects",
}
# Accepted so older config files still load, but they no longer do anything.
DEPRECATED = {
    "idle_seconds": "hibernation now requires real memory pressure; there is no idle-only timer",
    "idle_budget_mib": "idle agents holding memory is not memory pressure",
}
# Herdr error codes that will not change by retrying with the same pane state.
PERMANENT_CODES = {"confirmation_required"}
# herdr-projects groups (src/thread.rs::group) whose thread is waiting on the user.
WAITING_GROUPS = {"waiting-on-you": "waiting on you", "ready-for-review": "ready for review",
                  "landing": "landing (approved pull request)"}
ELIGIBLE_GROUPS = {"idle", "resolved"}


class GuardError(RuntimeError):
    def __init__(self, message, permanent=False):
        super().__init__(message)
        self.permanent = permanent


def fmt_duration(seconds):
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h{seconds % 3600 // 60:02d}m"
    return f"{seconds // 86400}d{seconds % 86400 // 3600}h"


def fmt_percent(value):
    return f"{value:.1f}".rstrip("0").rstrip(".") + "%"


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".guard-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(data, out, indent=2, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        dfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        return {} if default is None else default


def config_load(path):
    overrides = read_json(path)
    if not isinstance(overrides, dict) or set(overrides) - set(DEFAULTS) - set(DEPRECATED):
        raise GuardError("Invalid config or unknown setting; automatic actions stopped")
    cfg = DEFAULTS | {k: v for k, v in overrides.items() if k not in DEPRECATED}
    for key, default in DEFAULTS.items():
        value = cfg[key]
        if isinstance(default, bool):
            valid = isinstance(value, bool)
        elif isinstance(default, (int, float)):
            valid = (type(value) in (int, float) and math.isfinite(value) and value > 0)
        else:
            valid = isinstance(value, type(default))
        if not valid:
            raise GuardError(f"Invalid setting: {key}")
    for key in ("protected_panes", "protected_projects"):
        if any(not isinstance(x, str) for x in cfg[key]):
            raise GuardError(f"{key} must contain strings")
    for key in ("available_percent", "recovery_percent", "host_available_percent", "host_recovery_percent"):
        if cfg[key] >= 100:
            raise GuardError(f"{key} must be below 100")
    if cfg["interval_seconds"] < 5 or cfg["quiet_seconds"] < 30:
        raise GuardError("Minimum interval is 5 seconds; minimum quiet observation is 30 seconds")
    if not cfg["herdr_projects_bin"]:
        raise GuardError("herdr_projects_bin must not be empty")
    if cfg["failure_backoff_max_seconds"] < cfg["failure_backoff_seconds"]:
        raise GuardError("failure_backoff_max_seconds must be at least failure_backoff_seconds")
    if cfg["recovery_percent"] < cfg["available_percent"] or cfg["host_recovery_percent"] < cfg["host_available_percent"]:
        raise GuardError("Recovery thresholds must be at least the pressure thresholds")
    for key in ("max_actions_per_cycle", "max_checkpoints"):
        if type(cfg[key]) is not int:
            raise GuardError(f"{key} must be an integer")
    return cfg


def ignored_settings(path):
    data = read_json(path)
    return sorted(k for k in data if k in DEPRECATED) if isinstance(data, dict) else []


class API:
    def __init__(self, path):
        self.path = str(Path(path).expanduser().absolute())

    def call(self, method, **params):
        request_id = "memory-guard"
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(10)
            conn.connect(self.path)
            conn.sendall(json.dumps({"id": request_id, "method": method, "params": params}).encode() + b"\n")
            with conn.makefile("rb") as stream:
                line = stream.readline(8 * MIB + 1)
            if len(line) > 8 * MIB:
                raise GuardError("Oversize Herdr response")
        result = json.loads(line)
        if result.get("id") != request_id or "error" in result:
            error = result.get("error", "invalid response")
            code = error.get("code") if isinstance(error, dict) else None
            raise GuardError(f"Herdr {method} failed: {error}", permanent=code in PERMANENT_CODES)
        return result["result"]

    def server_identity(self):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(5)
            conn.connect(self.path)
            pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.getuid():
            raise GuardError("Herdr socket must belong to the current user")
        proc = read_proc(pid)
        if not proc:
            raise GuardError("Cannot verify Herdr server process")
        return f"{Path('/proc/sys/kernel/random/boot_id').read_text().strip()}:{pid}:{proc.start}"


@dataclasses.dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    pgrp: int
    session: int
    start: int
    ticks: int
    rss: int
    swap: int
    name: str


def read_proc(pid, root=Path("/proc")):
    try:
        folder = root / str(pid)
        if folder.stat().st_uid != os.getuid():
            return None
        raw = (folder / "stat").read_text()
        end = raw.rindex(")")
        name, fields = raw[raw.index("(") + 1:end], raw[end + 2:].split()
        if fields[0] == "Z":
            return None
        status = (folder / "status").read_text()
        swap = re.search(r"^VmSwap:\s+(\d+)", status, re.M)
        return Proc(int(pid), int(fields[1]), int(fields[2]), int(fields[3]),
                    int(fields[19]), int(fields[11]) + int(fields[12]),
                    int(fields[21]) * os.sysconf("SC_PAGE_SIZE"),
                    int(swap[1]) * 1024 if swap else 0, name)
    except (OSError, ValueError, IndexError):
        return None


def process_table():
    table = {}
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit() and (proc := read_proc(int(entry.name))):
            table[proc.pid] = proc
    return table


def descendants(root, table):
    found, frontier = {}, [root]
    children = {}
    for proc in table.values():
        children.setdefault(proc.ppid, []).append(proc.pid)
    while frontier:
        pid = frontier.pop()
        if pid in found or pid not in table:
            continue
        found[pid] = table[pid]
        frontier.extend(children.get(pid, []))
    return found


def process_scope(info, table, kind):
    """Only the exact foreground process group descended from this pane's shell."""
    shell = table.get(info.get("shell_pid"))
    fg = info.get("foreground_process_group_id")
    if not shell or shell.name not in SHELLS or not fg or fg == shell.pgrp:
        return {}, []
    tree = descendants(shell.pid, table)
    foreground = {p.pid: p for p in tree.values() if p.pgrp == fg and p.pid != shell.pid}
    if not foreground or not any(p.name == kind for p in foreground.values()):
        return {}, []
    roots = sorted(pid for pid, p in foreground.items() if p.ppid not in foreground)
    scope = {}
    for pid in roots:
        scope.update(descendants(pid, table))
    if shell.pid in scope or os.getpid() in scope:
        return {}, []
    return scope, roots


def parse_time(value):
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError, AttributeError):
        return None


def project_records(root, socket_path):
    # coordinators: pane id -> project slug (membership tests work like a set).
    records, coordinators = {}, {}
    root = Path(root).expanduser()
    for project in root.iterdir() if root.exists() else []:
        if not project.is_dir() or project.name.startswith("."):
            continue
        try:
            binding = read_json(project / ".state/coordinator.json")
            if binding.get("socket") != socket_path:
                continue
            if binding.get("pane_id"):
                coordinators[binding["pane_id"]] = project.name
            for file in (project / "threads").glob("*.toml"):
                try:
                    record = tomllib.loads(file.read_text())
                    if record.get("machine") or not record.get("pane_id"):
                        continue
                    record["project"] = project.name
                    record["record_path"] = str(file)
                    records[record["pane_id"]] = record
                except (OSError, ValueError):
                    continue
        except (OSError, ValueError):
            continue
    return records, coordinators


def identity(pane):
    session = pane.get("agent_session") or {}
    return [pane.get("terminal_id"), pane.get("agent"), session.get("kind"), session.get("value")]


def activity(pane):
    # Pane revisions also change on metadata, resizing, and UI bookkeeping.
    # AgentInfo state sequences and passive terminal contents track actual activity.
    return [pane.get("state_change_seq"), pane.get("agent_status"), pane.get("_screen_digest")]


def resume_args(kind, session):
    if session.get("kind") != "id" or not session.get("value") or session.get("agent") != kind:
        raise GuardError("No matching native session ID; cannot hibernate")
    value = session["value"]
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,128}", value):
        raise GuardError("Unsafe or unsupported session ID")
    flags = {"claude": "--resume", "codex": "resume", "opencode": "--session"}
    if kind not in flags:
        raise GuardError("Agent does not have a supported resume adapter")
    return [flags[kind], value]


def protection(pane, record, coordinators, cfg):
    pid = pane["pane_id"]
    tokens = pane.get("tokens") or {}
    project = (record or {}).get("project", tokens.get("hp_project"))
    if pane.get("focused"):
        return "focused"
    if pid in cfg["protected_panes"] or project in cfg["protected_projects"]:
        return "pinned"
    group = tokens.get("hp_group", "").split("!")
    if cfg["protect_coordinators"] and (pid in coordinators or (len(group) > 1 and group[1] == "0") or pane.get("name", "").startswith("hpc-")):
        return "coordinator"
    if cfg["managed_threads_only"] and not record:
        return "unmanaged"
    if record and (record.get("prompt_pending") or record.get("brief_claimed") or record.get("error") or record.get("brief_stuck")):
        return "thread requires attention"
    if not pane.get("agent"):
        return "no agent in pane"
    if pane.get("agent_status") not in SAFE_STATES:
        return f"agent is {pane.get('agent_status') or 'in an unknown state'}"
    try:
        resume_args(pane.get("agent"), pane.get("agent_session") or {})
    except GuardError as exc:
        return str(exc)
    return ""


def memory_sample(cfg, state):
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        values[key] = int(value.strip().split()[0]) * 1024
    available = 100 * values["MemAvailable"] / values["MemTotal"]
    psi = 0.0
    with contextlib.suppress(OSError, ValueError):
        psi = float(re.search(r"some avg10=([\d.]+)", Path("/proc/pressure/memory").read_text())[1])
    host = state.get("host_sample", {})
    now = time.time()
    if cfg["sample_windows_host"] and now - host.get("at", 0) >= 120 and "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower():
        exe = Path("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
        if exe.exists():
            try:
                command = "$m=Get-CimInstance Win32_OperatingSystem; Write-Output ([string]$m.TotalVisibleMemorySize + ',' + [string]$m.FreePhysicalMemory)"
                out = subprocess.run([str(exe), "-NoProfile", "-NonInteractive", "-Command", command], capture_output=True, text=True, timeout=8, check=True)
                total, free = map(int, out.stdout.strip().split(","))
                host = {"at": now, "available_percent": free / total * 100}
            except (OSError, ValueError, subprocess.SubprocessError):
                host = {"at": now, "error": "Windows memory sample unavailable"}
        state["host_sample"] = host
    host_percent = host.get("available_percent") if now - host.get("at", 0) < 300 else None
    return {"available_percent": round(available, 2), "available_mib": round(values["MemAvailable"] / MIB),
            "swap_used_mib": round((values["SwapTotal"] - values["SwapFree"]) / MIB),
            "psi_some_avg10": psi, "host_available_percent": host_percent}


def pressure_level(memory, cfg, previous):
    """Genuine memory pressure only, each reason with its numbers and threshold.

    While already under pressure the recovery thresholds apply (hysteresis).
    Idle agents holding memory is not pressure: a machine with headroom keeps them.
    """
    reasons = []
    linux = cfg["recovery_percent" if previous else "available_percent"]
    if memory["available_percent"] < linux:
        mib = memory.get("available_mib")
        amount = f" ({mib} MiB)" if mib is not None else ""
        reasons.append(f"Linux MemAvailable {fmt_percent(memory['available_percent'])}{amount} is below "
                       f"{fmt_percent(linux)}" + (" (recovery threshold)" if previous else ""))
    host = memory.get("host_available_percent")
    host_limit = cfg["host_recovery_percent" if previous else "host_available_percent"]
    if host is not None and host < host_limit:
        reasons.append(f"Windows host available memory {fmt_percent(host)} is below {fmt_percent(host_limit)}"
                       + (" (recovery threshold)" if previous else ""))
    if memory["psi_some_avg10"] >= cfg["psi_some_avg10"]:
        reasons.append(f"Linux memory stall PSI some avg10 {memory['psi_some_avg10']:g} is at or above {cfg['psi_some_avg10']:g}")
    return reasons


def headroom(memory, cfg):
    parts = [f"Linux MemAvailable {fmt_percent(memory['available_percent'])}"
             + (f" ({memory['available_mib']} MiB)" if memory.get("available_mib") is not None else "")
             + f" >= {fmt_percent(cfg['available_percent'])}",
             f"PSI some avg10 {memory['psi_some_avg10']:g} < {cfg['psi_some_avg10']:g}"]
    if memory.get("host_available_percent") is not None:
        parts.append(f"Windows host {fmt_percent(memory['host_available_percent'])} >= {fmt_percent(cfg['host_available_percent'])}")
    return ", ".join(parts)


def projects_bin(cfg):
    name = cfg["herdr_projects_bin"]
    found = shutil.which(name)
    if not found and "/" not in name:
        # systemd user services often lack ~/.local/bin on PATH.
        local = Path.home() / ".local/bin" / name
        if local.is_file() and os.access(local, os.X_OK):
            found = str(local)
    return found


def thread_states(cfg, slugs):
    """Live thread state from `herdr-projects thread list <slug> --json`, keyed by (project, thread id).

    This is the same grouping herdr-projects shows the user (waiting on you,
    ready for review, working, idle...). Failures are returned per project so
    callers fail closed.
    """
    exe = projects_bin(cfg)
    states, errors = {}, {}
    for slug in sorted(slugs):
        if not exe:
            errors[slug] = f"{cfg['herdr_projects_bin']} not found"
            continue
        try:
            out = subprocess.run([exe, "--root", str(Path(cfg["projects_root"]).expanduser()), "thread", "list", slug, "--json"],
                                 capture_output=True, text=True, timeout=20, check=True)
            data = json.loads(out.stdout)
            if not isinstance(data, list):
                raise ValueError("unexpected thread list output")
            for thread in data:
                if isinstance(thread, dict) and thread.get("id"):
                    states[(slug, thread["id"])] = thread
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            errors[slug] = str(exc)[:200]
    return states, errors


def thread_hold(record, live, now, cfg):
    """(rule, reason) when a managed thread's agent must stay, else ("", "")."""
    if live is None:
        return "thread state unavailable", "thread state unavailable from herdr-projects; failing closed"
    group = live.get("group_token")
    if group in WAITING_GROUPS:
        return "waiting on the user", f"waiting on the user: thread is {WAITING_GROUPS[group]}"
    if group == "working":
        return "thread is working", "thread is working"
    if group not in ELIGIBLE_GROUPS:
        return "thread state unavailable", f"unrecognised thread group {group!r}; failing closed"
    thread = record | live
    if thread.get("status") != "resolved":
        if thread.get("report_hash") and thread.get("report_hash") != thread.get("acked_report_hash"):
            return "waiting on the user", "waiting on the user: unacknowledged report"
        if str(thread.get("pr_state", "")).lower() == "open":
            return "waiting on the user", "waiting on the user: open pull request"
        if "waiting" in str(thread.get("activity", "")).lower():
            return "waiting on the user", f"waiting on the user: agent reported {thread['activity']!r}"
    stamps = [parse_time(thread.get(k)) for k in ("last_state_change", "last_report_change", "launched_at", "brief_seen_at")]
    stamps = [s for s in stamps if s]
    if stamps:
        age = now - max(stamps)
        if age < cfg["recent_work_seconds"]:
            return "recently worked", (f"recently worked: last thread activity {fmt_duration(age)} ago "
                                       f"(protected for {fmt_duration(cfg['recent_work_seconds'])})")
    return "", ""


def native_resume_command(kind, args, cwd):
    command = shlex.join([kind, *args])
    return f"cd {shlex.quote(cwd)} && {command}" if cwd else command


def safe_subject(subject):
    cleaned = "".join(c.lower() if c.isascii() and (c.isalnum() or c == "-") else "-" for c in subject)[:40].strip("-")
    return cleaned or "item"


def toml_string(value):
    # JSON string escapes are a subset of TOML basic-string escapes.
    return json.dumps(value, ensure_ascii=True)


def write_inbox(projects_root, slug, subject, event, summary):
    """Leave an item in a herdr-projects inbox, in its own file format (src/inbox.rs).

    The herdr-projects ticker announces unseen items to the coordinator only
    when it is idle and its input box is empty, so this never types into a busy agent.
    """
    project = Path(projects_root).expanduser() / slug
    if not slug or "/" in slug or slug.startswith(".") or not (project / "PROJECT.md").is_file():
        raise GuardError(f"Project {slug!r} not found for coordinator notification")
    (project / "inbox").mkdir(exist_ok=True)
    (project / ".state").mkdir(exist_ok=True)
    with (project / ".state/lock").open("a") as lock:
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise GuardError("herdr-projects project lock is busy")
                time.sleep(0.05)
        now = dt.datetime.now(dt.timezone.utc)
        item_id = f"{now:%Y%m%dT%H%M%SZ}-memory-guard-{safe_subject(subject)}-mg{time.time_ns() % 10**12}"
        clean = "".join(" " if ord(c) < 32 or ord(c) == 127 else c for c in summary)
        front = "".join(f"{key} = {toml_string(value)}\n" for key, value in [
            ("id", item_id), ("kind", "memory-guard"), ("subject", subject),
            ("created", f"{now:%Y-%m-%dT%H:%M:%SZ}"), ("summary", clean), ("event", event)])
        path = project / "inbox" / f"{item_id}.md"
        fd, name = tempfile.mkstemp(prefix=".memory-guard-", dir=path.parent)
        try:
            with os.fdopen(fd, "w") as out:
                out.write(f"+++\n{front}+++\n")
            os.chmod(name, 0o644)
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    return item_id


def checkpoint_key(data):
    pane = data.get("pane") or {}
    session = pane.get("agent_session") or {}
    return (pane.get("pane_id"), pane.get("terminal_id"), session.get("value"), (data.get("decision") or {}).get("action"))


def checkpoint_succeeded(data):
    outcome = data.get("outcome") or {}
    return outcome.get("status") in {"hibernated", "partial", "closed"} or (
        outcome.get("action") in {"hibernate", "close-resolved-shell"} and "error" not in outcome and outcome.get("status") != "aborted")


def prune_checkpoints(directory, apply=False):
    """Remove superseded duplicate checkpoints of attempts that changed nothing.

    For each (pane, terminal, session, action) only the newest unsuccessful
    attempt is kept, and none once a later attempt succeeded. Successful
    hibernations and unreadable files are always kept.
    """
    groups = {}
    for path in sorted(Path(directory).glob("*.json"), key=lambda p: (int(p.name.split("-")[0]) if p.name.split("-")[0].isdigit() else 0, p.name)):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(data, dict):
            groups.setdefault(checkpoint_key(data), []).append((path, data))
    remove = []
    for items in groups.values():
        last_success = max((i for i, (_, d) in enumerate(items) if checkpoint_succeeded(d)), default=-1)
        failed = [i for i, (_, d) in enumerate(items) if not checkpoint_succeeded(d)]
        for i in failed:
            if i != failed[-1] or i < last_success:
                remove.append(items[i][0])
    if apply:
        for path in remove:
            path.unlink(missing_ok=True)
    return {"remove": [str(p) for p in remove], "applied": apply}


DECISION_ORDER = {"hibernated": 0, "closed": 0, "failed": 0, "ready": 1, "watching": 2, "backoff": 3, "protected": 4}


def render(report):
    """Human-readable dry-run output: one line per pane with its decision and reason."""
    m = report["memory"]
    host = "n/a" if m.get("host_available_percent") is None else fmt_percent(m["host_available_percent"])
    lines = [f"Memory: Linux MemAvailable {fmt_percent(m['available_percent'])} ({m.get('available_mib', '?')} MiB), "
             f"PSI some avg10 {m['psi_some_avg10']:g}, Windows host {host}, swap used {m.get('swap_used_mib', '?')} MiB",
             "Pressure: " + ("; ".join(report["pressure"]) if report["pressure"] else f"none ({report['headroom']})"),
             "Mode: " + ("apply" if report["apply"] and report["enabled"] else "dry run (no signals, no pane changes)")]
    if report.get("ignored_settings"):
        lines.append("Ignored settings: " + ", ".join(report["ignored_settings"]))
    if report.get("thread_state_errors"):
        lines.append("Thread state errors: " + "; ".join(f"{k}: {v}" for k, v in report["thread_state_errors"].items()))
    lines.append(f"{len(report['decisions'])} panes ({report['agents']} agents); "
                 f"protected by rule: " + ", ".join(f"{k} {v}" for k, v in sorted(report["protected"].items(), key=lambda kv: -kv[1])))
    lines.append("")
    lines.append(f"{'PANE':<10} {'DECISION':<10} {'THREAD':<32} {'AGENT':<16} REASON")
    for d in sorted(report["decisions"], key=lambda d: (DECISION_ORDER.get(d["decision"], 9), d.get("project") or "", d["pane_id"])):
        who = "/".join(x for x in (d.get("project"), d.get("thread")) if x) or "-"
        agent = f"{d['agent']}({d.get('agent_status') or '?'})" if d.get("agent") else "-"
        lines.append(f"{d['pane_id']:<10} {d['decision']:<10} {who:<32} {agent:<16} {d['reason']}")
    for a in report["actions"]:
        lines.append(f"ACTION {a['pane_id']} {a.get('action')}: " + (f"FAILED {a['error']}" if "error" in a else a.get("status", "done")))
    for pid, h in sorted((report.get("hibernated") or {}).items()):
        lines.append(f"HIBERNATED {pid} {h.get('project')}/{h.get('thread')}: resume with {h.get('resume_command')}")
    return "\n".join(lines)


def plugin_enabled(api):
    plugins = api.call("plugin.list").get("plugins", [])
    return any(p.get("plugin_id") == PLUGIN and p.get("enabled") is True for p in plugins)


class Guard:
    def __init__(self, api, config_dir, state_dir):
        self.api = api
        self.config_dir, self.state_dir = Path(config_dir), Path(state_dir)
        self.config_path = self.config_dir / "config.json"
        self.key = hashlib.sha256(api.path.encode()).hexdigest()[:12]
        self.directory = self.state_dir / self.key
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_path = self.directory / "state.json"
        self.status_path = self.directory / "status.json"

    @contextlib.contextmanager
    def locked(self):
        with (self.directory / "cycle.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def cycle(self, apply=False):
        with self.locked():
            return self._cycle(apply)

    def observe_pane(self, pane, agent=None):
        pane = dict(pane)
        if pane.get("agent"):
            if agent is None:
                agent = self.api.call("agent.get", target=pane["pane_id"])["agent"]
            if identity(agent) != identity(pane):
                raise GuardError("Agent changed while observing pane")
            if agent.get("agent_status") != pane.get("agent_status"):
                raise GuardError("Pane became active or status changed while observing")
            focused = bool(pane.get("focused") or agent.get("focused"))
            pane.update(agent)
            pane["focused"] = focused
        read = self.api.call("pane.read", pane_id=pane["pane_id"], source="detection", lines=80, strip_ansi=True)["read"]
        if not isinstance(read.get("text"), str):
            raise GuardError("Passive terminal content unavailable")
        pane["_screen_digest"] = hashlib.sha256(read["text"].encode()).hexdigest()
        return pane

    def _cycle(self, apply):
        cfg = config_load(self.config_path)
        now = time.time()
        server = self.api.server_identity()
        state = read_json(self.state_path)
        if state.get("server") != server or state.get("observation_version") != 3:
            state = {"server": server, "observation_version": 3, "observations": {}, "failures": {}}
        state.setdefault("failures", {})
        snapshot = self.api.call("session.snapshot")["snapshot"]
        agents = {a["pane_id"]: a for a in snapshot.get("agents", [])}
        table = process_table()
        table_sampled_at = time.monotonic()
        records, coordinators = project_records(cfg["projects_root"], self.api.path)
        memory = memory_sample(cfg, state)
        pressure = pressure_level(memory, cfg, state.get("pressure", False))
        decisions, protected = {}, Counter()

        def note(pane, record, decision, reason, rule=None):
            tokens = pane.get("tokens") or {}
            project = (record or {}).get("project") or tokens.get("hp_project")
            if not project and isinstance(coordinators, dict):
                project = coordinators.get(pane["pane_id"])
            decisions[pane["pane_id"]] = {
                "pane_id": pane["pane_id"], "project": project,
                "thread": (record or {}).get("id"), "agent": pane.get("agent"), "agent_status": pane.get("agent_status"),
                "decision": decision, "reason": reason}
            if decision == "protected":
                protected[rule or reason] += 1

        admitted = []
        for pane in snapshot["panes"]:
            pid = pane["pane_id"]
            # Global focus is authoritative even if a PaneInfo omitted its flag.
            if pid == snapshot.get("focused_pane_id"):
                pane = pane | {"focused": True}
            record = records.get(pid)
            reason = protection(pane, record, coordinators, cfg)
            shell_candidate = bool(cfg["close_resolved_shells"] and record and record.get("status") == "resolved"
                                   and not pane.get("agent") and not pane.get("focused") and pid not in cfg["protected_panes"]
                                   and record["project"] not in cfg["protected_projects"] and pid not in coordinators)
            if reason and not shell_candidate:
                note(pane, record, "protected", reason)
                continue
            admitted.append((pane, record, shell_candidate))
        slugs = {record["project"] for _, record, shell in admitted if record and not shell}
        threads, thread_errors = thread_states(cfg, slugs) if slugs else ({}, {})

        observations, candidates, scopes, signatures = {}, [], {}, {}
        for pane, record, shell_candidate in admitted:
            pid = pane["pane_id"]
            live = threads.get((record["project"], record.get("id"))) if record else None
            if record and not shell_candidate:
                rule, hold = thread_hold(record, live, now, cfg)
                if hold:
                    note(pane, record, "protected", hold, rule)
                    continue
            signatures[pid] = failure_signature(pane, record, live)
            failure = state["failures"].get(pid)
            if failure and failure.get("signature") != signatures[pid]:
                state["failures"].pop(pid)
                failure = None
            if failure and (failure.get("permanent") or now < failure["next_at"]):
                wait = ("not retrying until the pane or thread changes" if failure.get("permanent")
                        else f"next attempt in {fmt_duration(failure['next_at'] - now)}")
                note(pane, record, "backoff", f"{failure['count']} failed attempt(s), last: {failure['error']}; {wait}", "backoff")
                continue
            try:
                info = self.api.call("pane.process_info", pane_id=pid)["process_info"]
                pane = self.observe_pane(pane, agents.get(pid))
            except (GuardError, OSError) as exc:
                note(pane, record, "protected", f"process info unavailable: {str(exc)[:120]}", "process info unavailable")
                continue
            if shell_candidate:
                shell = table.get(info.get("shell_pid"))
                tree = descendants(shell.pid, table) if shell else {}
                if not shell or shell.name not in SHELLS or info.get("foreground_process_group_id") != shell.pgrp or len(tree) != 1:
                    note(pane, record, "protected", "resolved pane has running processes")
                    continue
                scope, roots, action = tree, [shell.pid], "close-resolved-shell"
            else:
                scope, roots = process_scope(info, table, pane.get("agent"))
                action = "hibernate"
                if not scope:
                    note(pane, record, "protected", "unverified foreground agent")
                    continue
            fingerprint = [identity(pane), [[p.pid, p.start] for p in sorted(scope.values(), key=lambda p: p.pid)]]
            ticks = sum(p.ticks for p in scope.values())
            prior = state.get("observations", {}).get(pid, {})
            same = prior.get("fingerprint") == fingerprint
            # A long monitoring gap invalidates all quiet evidence.
            gap = now - prior.get("at", now)
            continuous = same and 0 < gap <= max(90, cfg["interval_seconds"] * 3)
            cpu = max(0, ticks - prior.get("ticks", ticks)) / os.sysconf("SC_CLK_TCK") / max(gap, 0.01) * 100
            quiet = continuous and prior.get("activity") == activity(pane) and cpu <= cfg["max_cpu_percent"]
            seed = now
            if record and (record.get("last_state") == pane.get("agent_status") or shell_candidate):
                seed = min(now, max(parse_time(record.get("last_state_change")) or now,
                                    parse_time(record.get("updated")) or now))
            observation = {"fingerprint": fingerprint, "activity": activity(pane), "ticks": ticks, "at": now,
                           "cpu_sampled_at": table_sampled_at,
                           "quiet_since": prior["quiet_since"] if quiet else now,
                           "idle_since": prior["idle_since"] if continuous else seed,
                           "samples": prior.get("samples", 0) + 1 if quiet else 1}
            if continuous and (not quiet or pane.get("focused")):
                observation["idle_since"] = now
            observations[pid] = observation
            rss, swap = sum(p.rss for p in scope.values()), sum(p.swap for p in scope.values())
            candidate = {"pane_id": pid, "action": action, "agent": pane.get("agent"),
                         "project": (record or {}).get("project"), "thread": (record or {}).get("id"),
                         "rss_mib": round(rss / MIB, 1), "swap_mib": round(swap / MIB, 1),
                         "idle_seconds": int(now - observation["idle_since"]),
                         "quiet_seconds": int(now - observation["quiet_since"]), "ready": False, "reason": ""}
            candidates.append(candidate)
            scopes[pid] = (pane, record, scope, roots, info, observation)

        pressure_text = "; ".join(pressure)
        for c in candidates:
            size, idle, quiet = c["rss_mib"] + c["swap_mib"], c["idle_seconds"], c["quiet_seconds"]
            ready = False
            if c["action"] == "close-resolved-shell":
                need = cfg["resolved_shell_seconds"]
                if idle < need:
                    why = f"empty shell of a resolved thread, idle {fmt_duration(idle)} of {fmt_duration(need)} before closing"
                elif quiet < cfg["quiet_seconds"]:
                    why = f"empty shell of a resolved thread, quiet {fmt_duration(quiet)} of {fmt_duration(cfg['quiet_seconds'])}"
                else:
                    ready, why = True, (f"thread resolved and its empty shell pane idle {fmt_duration(idle)} "
                                        f"(>= {fmt_duration(need)}); closes the pane, keeps the worktree")
            elif not pressure:
                why = f"no memory pressure: {headroom(memory, cfg)}"
            elif idle < cfg["pressure_idle_seconds"]:
                why = f"memory pressure ({pressure_text}) but agent idle only {fmt_duration(idle)} of {fmt_duration(cfg['pressure_idle_seconds'])}"
            elif quiet < cfg["quiet_seconds"]:
                why = f"memory pressure ({pressure_text}) but quiet only {fmt_duration(quiet)} of {fmt_duration(cfg['quiet_seconds'])}"
            elif size < cfg["min_reclaim_mib"]:
                why = f"memory pressure ({pressure_text}) but would free only {size:.0f} MiB (< {cfg['min_reclaim_mib']} MiB)"
            else:
                ready, why = True, (f"memory pressure: {pressure_text}; agent idle {fmt_duration(idle)}, "
                                    f"quiet {fmt_duration(quiet)}; frees ~{size:.0f} MiB")
            c["ready"], c["reason"] = ready, why
            pane, record = scopes[c["pane_id"]][:2]
            note(pane, record, "ready" if ready else "watching", why)
        candidates.sort(key=lambda c: (c["ready"], c["action"] == "hibernate", c["rss_mib"] + c["swap_mib"], c["idle_seconds"]), reverse=True)
        present = {p["pane_id"] for p in snapshot["panes"]}
        state.update(observations=observations, pressure=bool(pressure),
                     failures={k: v for k, v in state["failures"].items() if k in present})
        atomic_json(self.state_path, state)
        hibernated = self.refresh_registry(snapshot)
        report = {"at": now, "enabled": cfg["enabled"], "apply": apply, "server": server,
                  "panes": len(snapshot["panes"]), "agents": len(snapshot.get("agents", [])),
                  "memory": memory, "pressure": pressure, "headroom": headroom(memory, cfg),
                  "eligible_idle_mib": round(sum(c["rss_mib"] + c["swap_mib"] for c in candidates if c["action"] == "hibernate")),
                  "protected": dict(protected), "thread_state_errors": thread_errors,
                  "ignored_settings": ignored_settings(self.config_path),
                  "candidates": candidates, "actions": [], "hibernated": hibernated, "decisions": []}
        if apply and cfg["enabled"]:
            for c in [c for c in candidates if c["ready"]][:cfg["max_actions_per_cycle"]]:
                pid = c["pane_id"]
                try:
                    result = self.reclaim(c, scopes[pid], cfg, coordinators, server)
                    state["failures"].pop(pid, None)
                    self.after_action(result, c, scopes[pid], cfg)
                    decisions[pid].update(decision="closed" if c["action"] == "close-resolved-shell" else "hibernated")
                except (GuardError, OSError, ValueError) as exc:
                    count = state["failures"].get(pid, {}).get("count", 0) + 1
                    permanent = getattr(exc, "permanent", False)
                    delay = min(cfg["failure_backoff_max_seconds"], cfg["failure_backoff_seconds"] * 2 ** (count - 1))
                    state["failures"][pid] = {"count": count, "error": str(exc)[:300], "at": now, "next_at": now + delay,
                                              "permanent": permanent, "signature": signatures[pid]}
                    result = {"pane_id": pid, "action": c["action"], "project": c["project"], "thread": c["thread"],
                              "reason": c["reason"], "error": str(exc),
                              "retry": "not until the pane or thread changes" if permanent else f"in {fmt_duration(delay)}"}
                    decisions[pid].update(decision="failed")
                self.audit(result)
                report["actions"].append(result)
                # Treat ambiguous partial actions as consumed; reobserve before any retry.
                state["observations"].pop(pid, None)
            report["hibernated"] = self.registry()
        report["decisions"] = list(decisions.values())
        atomic_json(self.state_path, state)
        atomic_json(self.status_path, report)
        return report

    # --- hibernated registry (read by coordinators' tools and dashboards) -------

    @property
    def registry_path(self):
        return self.directory / "hibernated.json"

    def registry(self):
        return read_json(self.registry_path).get("hibernated", {})

    def save_registry(self, entries):
        atomic_json(self.registry_path, {"updated": time.time(), "socket": self.api.path, "hibernated": entries})

    def refresh_registry(self, snapshot):
        entries = self.registry()
        panes = {p["pane_id"]: p for p in snapshot["panes"]}
        changed = False
        for pid, entry in list(entries.items()):
            pane = panes.get(pid)
            if pane and pane.get("agent"):
                # Someone resumed it (or reused the pane) outside `guard.py resume`.
                entries.pop(pid)
                self.audit({"action": "resumed-elsewhere", "pane_id": pid, "thread": entry.get("thread")})
                changed = True
            elif entry.get("pane_present") != bool(pane):
                entry["pane_present"] = bool(pane)
                changed = True
        if changed:
            self.save_registry(entries)
        return entries

    def resume_command(self, pane_id):
        return shlex.join(["python3", str(Path(__file__).resolve()), "resume", "--pane", pane_id, "--socket", self.api.path,
                           "--config-dir", str(self.config_dir), "--state-dir", str(self.state_dir)])

    def notify(self, cfg, record, event, summary):
        if not cfg["notify_coordinators"] or not record or not record.get("project"):
            return None
        return write_inbox(cfg["projects_root"], record["project"], record.get("id") or "memory-guard", event, summary)

    def after_action(self, result, candidate, evidence, cfg):
        pane, record = evidence[0], evidence[1]
        pid = pane["pane_id"]
        thread = (record or {}).get("id") or "unmanaged agent"
        result.update(project=(record or {}).get("project"), thread=(record or {}).get("id"), reason=candidate["reason"])
        if candidate["action"] == "hibernate":
            args = resume_args(pane["agent"], pane["agent_session"])
            cwd = pane.get("foreground_cwd") or pane.get("cwd") or (record or {}).get("cwd") or ""
            entry = {"pane_id": pid, "project": result["project"], "thread": result["thread"], "agent": pane["agent"],
                     "session_id": pane["agent_session"]["value"], "cwd": cwd, "status": result.get("status"),
                     "reason": candidate["reason"], "checkpoint": result["checkpoint"], "hibernated_at": time.time(),
                     "resume_command": self.resume_command(pid),
                     "native_resume_command": native_resume_command(pane["agent"], args, cwd), "pane_present": True}
            entries = self.registry()
            entries[pid] = entry
            self.save_registry(entries)
            event = "hibernated by Memory Guard"
            summary = (f"{thread} ({pane['agent']} in pane {pid}) was hibernated by Memory Guard "
                       f"({result.get('status')}). Reason: {candidate['reason']}. Checkpoint: {result['checkpoint']}. "
                       f"Resume: {entry['resume_command']} . If the pane is gone: {entry['native_resume_command']}")
        else:
            event = "pane closed by Memory Guard"
            summary = (f"{thread}: its empty shell pane {pid} was closed by Memory Guard. Reason: {candidate['reason']}. "
                       f"Checkpoint with recent scrollback: {result['checkpoint']}")
        try:
            result["notified"] = self.notify(cfg, record, event, summary)
        except (GuardError, OSError) as exc:
            result["notify_error"] = str(exc)

    def reclaim(self, candidate, evidence, cfg, coordinators, server):
        pane, record, scope, roots, info, observation = evidence
        pid = pane["pane_id"]
        if self.api.server_identity() != server:
            raise GuardError("Herdr restarted during observation")
        # Config is reread at the mutation boundary so pause/protect takes effect immediately.
        latest_cfg = config_load(self.config_path)
        if not latest_cfg["enabled"]:
            raise GuardError("Automatic reclamation is paused")
        records, latest_coordinators = project_records(cfg["projects_root"], self.api.path)
        if records.get(pid) != record:
            raise GuardError("Project record changed")
        current = self.observe_pane(self.api.call("pane.get", pane_id=pid)["pane"])
        if identity(current) != identity(pane) or activity(current) != activity(pane):
            raise GuardError("Pane became active or its occupant changed")
        if current.get("focused") or pid in latest_cfg["protected_panes"] or (record or {}).get("project") in latest_cfg["protected_projects"]:
            raise GuardError("Pane is now focused or protected")
        if candidate["action"] == "hibernate":
            reason = protection(current, record, latest_coordinators, latest_cfg)
            if reason:
                raise GuardError(reason)
            if record:
                # The coordinator or user may have just prompted or reviewed the thread.
                live = thread_states(latest_cfg, {record["project"]})[0].get((record["project"], record.get("id")))
                hold = thread_hold(record, live, time.time(), latest_cfg)[1]
                if hold:
                    raise GuardError(hold)
        elif not record or record.get("status") != "resolved":
            raise GuardError("Thread is no longer resolved")
        latest_info = self.api.call("pane.process_info", pane_id=pid)["process_info"]
        if (latest_info.get("shell_pid"), latest_info.get("foreground_process_group_id")) != (info.get("shell_pid"), info.get("foreground_process_group_id")):
            raise GuardError("Foreground process changed")
        fresh_table = process_table()
        if candidate["action"] == "hibernate":
            fresh_scope, fresh_roots = process_scope(latest_info, fresh_table, pane["agent"])
        else:
            fresh_scope = descendants(info["shell_pid"], fresh_table)
            fresh_roots = [info["shell_pid"]]
        if fresh_roots != roots or {(p.pid, p.start) for p in fresh_scope.values()} != {(p.pid, p.start) for p in scope.values()}:
            raise GuardError("Process tree changed")
        elapsed = max(0.01, time.monotonic() - observation["cpu_sampled_at"])
        delta_ticks = sum(max(0, fresh_scope[p.pid].ticks - p.ticks) for p in scope.values())
        # One scheduler tick of quantization slack, then the SAME quiet CPU
        # ceiling as observation. Normal idle CLI housekeeping is not zero CPU.
        allowed_ticks = 1 + elapsed * os.sysconf("SC_CLK_TCK") * latest_cfg["max_cpu_percent"] / 100
        if delta_ticks > allowed_ticks:
            raise GuardError("Processes became CPU-active during final validation")
        checkpoint = self.checkpoint(candidate, pane, record, scope, server, cfg)
        try:
            # Check again after checkpoint I/O and reading terminal output.
            current = self.observe_pane(self.api.call("pane.get", pane_id=pid)["pane"])
            if current.get("focused") or identity(current) != identity(pane) or activity(current) != activity(pane):
                raise GuardError("Pane changed while checkpointing")
            if candidate["action"] == "close-resolved-shell":
                # Never close a shell with even one background descendant.
                if len(descendants(info["shell_pid"], process_table())) != 1:
                    raise GuardError("Shell acquired a background job")
                self.api.call("pane.close", pane_id=pid)
                result = {"pane_id": pid, "action": candidate["action"], "status": "closed", "checkpoint": str(checkpoint)}
            else:
                def validate_before_signal():
                    final = self.observe_pane(self.api.call("pane.get", pane_id=pid)["pane"])
                    if final.get("focused") or identity(final) != identity(pane) or activity(final) != activity(pane):
                        raise GuardError("Pane changed before signaling")
                    if not config_load(self.config_path)["enabled"]:
                        raise GuardError("Automatic reclamation is paused")
                result = terminate_scope(scope, roots, validate=validate_before_signal)
                result.update(pane_id=pid, action="hibernate", checkpoint=str(checkpoint),
                              estimated_rss_mib=candidate["rss_mib"], estimated_swap_mib=candidate["swap_mib"])
        except (GuardError, OSError, ValueError) as exc:
            # Nothing was signaled or closed: record the aborted attempt in the same
            # checkpoint, which the next attempt reuses instead of adding another.
            self.mark_checkpoint(checkpoint, {"action": candidate["action"], "status": "aborted", "error": str(exc)})
            raise
        result["reason"] = candidate["reason"]
        self.mark_checkpoint(checkpoint, result)
        return result

    def mark_checkpoint(self, path, outcome):
        saved = read_json(path)
        saved["outcome"] = outcome
        atomic_json(path, saved)

    def checkpoint(self, candidate, pane, record, scope, server, cfg):
        directory = self.directory / "checkpoints"
        directory.mkdir(exist_ok=True, mode=0o700)
        files = sorted(directory.glob("*.json"), reverse=True)
        key = checkpoint_key({"pane": pane, "decision": candidate})
        reuse = None
        for file in files:
            try:
                previous = json.loads(file.read_text())
            except (OSError, ValueError):
                continue
            if checkpoint_key(previous) == key:
                # Reuse the newest checkpoint of this same occupant when its attempt changed nothing.
                if (previous.get("outcome") or {}).get("status") == "aborted":
                    reuse = file
                break
        if not reuse and (len(files) >= cfg["max_checkpoints"] or sum(f.stat().st_size for f in files) >= cfg["checkpoint_limit_mib"] * MIB):
            raise GuardError("Checkpoint budget reached; preserve existing recovery records and stop reclaiming", permanent=True)
        # Visible reads are passive. Asking an idle CLI for application-owned
        # history can scroll its UI and itself invalidate the quiet observation.
        output = self.api.call("pane.read", pane_id=pane["pane_id"], source="visible", lines=200, strip_ansi=True)
        data = {"at": time.time(), "server": server, "socket": self.api.path,
                "pane": pane, "thread": record, "terminal_output": output, "reason": candidate["reason"],
                "processes": [dataclasses.asdict(p) for p in scope.values()], "decision": candidate}
        if candidate["action"] == "hibernate":
            data["resume_args"] = resume_args(pane["agent"], pane["agent_session"])
            data["resume_command"] = self.resume_command(pane["pane_id"])
        existing = sum(f.stat().st_size for f in files if f != reuse)
        if existing + len(json.dumps(data, ensure_ascii=False).encode()) > cfg["checkpoint_limit_mib"] * MIB:
            raise GuardError("Checkpoint budget would be exceeded; automatic action stopped", permanent=True)
        path = reuse or directory / f"{time.time_ns()}-{pane['pane_id'].replace(':', '-')}.json"
        atomic_json(path, data)
        return path

    def audit(self, result):
        path = self.directory / "audit.jsonl"
        if path.exists() and path.stat().st_size > 2 * MIB:
            os.replace(path, path.with_suffix(".previous.jsonl"))
        with path.open("a") as out:
            out.write(json.dumps({"at": time.time(), **result}) + "\n")

    def prune(self, apply=False):
        with self.locked():
            plan = prune_checkpoints(self.directory / "checkpoints", apply)
            if apply and plan["remove"]:
                self.audit({"action": "prune-checkpoints", "removed": len(plan["remove"])})
            return plan

    def resume(self, pane_id, verify_seconds=15):
        with self.locked():
            path, saved = None, None
            for choice in sorted((self.directory / "checkpoints").glob("*.json"), reverse=True):
                data = read_json(choice)
                if data.get("pane", {}).get("pane_id") == pane_id and data.get("outcome", {}).get("action") == "hibernate" \
                        and data.get("outcome", {}).get("status") != "aborted":
                    path, saved = choice, data
                    break
            if not saved:
                raise GuardError("No successful hibernation checkpoint for this pane")
            pane = self.api.call("pane.get", pane_id=pane_id)["pane"]
            original = saved["pane"]
            if self.api.server_identity() != saved["server"] or pane.get("terminal_id") != original.get("terminal_id"):
                raise GuardError("Pane/server was replaced; use the checkpoint's native resume arguments in the original working directory")
            if pane.get("agent"):
                raise GuardError("Pane already has an agent")
            cwd = pane.get("foreground_cwd") or pane.get("cwd")
            original_cwd = original.get("foreground_cwd") or original.get("cwd")
            if cwd != original_cwd:
                raise GuardError("Working directory changed; return to the checkpoint's directory before resuming")
            info = self.api.call("pane.process_info", pane_id=pane_id)["process_info"]
            table = process_table()
            shell = table.get(info.get("shell_pid"))
            if not shell or shell.name not in SHELLS or shell.pgrp != info.get("foreground_process_group_id") or len(descendants(shell.pid, table)) != 1:
                raise GuardError("Pane is not an empty interactive shell")
            # Native CLI validates prompt readiness and refuses a busy pane.
            kind = original["agent"]
            args = resume_args(kind, original["agent_session"])
            session_id = original["agent_session"]["value"]
            name = original.get("name") or f"mg-{hashlib.sha256(pane_id.encode()).hexdigest()[:12]}"
            started = self.api.call("agent.start", pane_id=pane_id, kind=kind, name=name, args=args, timeout_ms=8000)
            verified = self.verify_session(pane_id, kind, session_id, verify_seconds)
            result = {"pane_id": pane_id, "agent": kind, "session_id": session_id, "session_verified": verified,
                      "args": args, "started": started, "checkpoint": str(path)}
            saved["resumed"] = {"at": time.time(), "session_verified": verified}
            atomic_json(path, saved)
            entries = self.registry()
            if entries.pop(pane_id, None) is not None:
                self.save_registry(entries)
            record = saved.get("thread") or {}
            thread = record.get("id") or "unmanaged agent"
            check = ("native session verified" if verified
                     else "herdr has not yet confirmed the native session id; check the pane")
            try:
                result["notified"] = self.notify(config_load(self.config_path), record, "resumed by Memory Guard",
                                                 f"{thread} ({kind} in pane {pane_id}) was resumed with {shlex.join([kind, *args])}; {check}.")
            except (GuardError, OSError) as exc:
                result["notify_error"] = str(exc)
            self.audit({"action": "resume", "pane_id": pane_id, "thread": record.get("id"), "session_verified": verified})
            return result

    def verify_session(self, pane_id, kind, session_id, seconds):
        """Confirm herdr sees the restarted agent on the saved native session."""
        deadline = time.monotonic() + seconds
        while True:
            try:
                agent = self.api.call("agent.get", target=pane_id)["agent"]
                session = agent.get("agent_session") or {}
                if agent.get("agent") == kind and session.get("value") == session_id:
                    return True
            except GuardError:
                pass
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.5)


def failure_signature(pane, record, live):
    """What must change before a failed action is worth trying again."""
    return [identity(pane), pane.get("agent_status"), (record or {}).get("status"), (live or {}).get("group_token")]


def terminate_scope(scope, roots, validate=None):
    """Bind pidfds BEFORE signaling. Never use killpg, a PID-only fallback, or SIGKILL."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise GuardError("Linux pidfd support is required; no unsafe PID fallback")
    fds = {}
    try:
        for pid, expected in scope.items():
            fd = os.pidfd_open(pid)
            fds[pid] = fd
            actual = read_proc(pid)
            if not actual or (actual.start, actual.ppid, actual.pgrp) != (expected.start, expected.ppid, expected.pgrp):
                raise GuardError("PID identity changed before signaling")
        if validate:
            validate()
        # Give the agent a chance to flush its native session and reap its children.
        for pid in roots:
            signal.pidfd_send_signal(fds[pid], signal.SIGTERM)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and any(read_proc(p) for p in roots):
            time.sleep(0.1)
        # Only children captured before the signal are eligible, including reparented MCPs.
        for pid, fd in fds.items():
            if pid not in roots:
                with contextlib.suppress(ProcessLookupError):
                    signal.pidfd_send_signal(fd, signal.SIGTERM)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and any(read_proc(p) for p in scope):
            time.sleep(0.1)
        remaining = [p for p in scope if (current := read_proc(p)) and current.start == scope[p].start]
        return {"signaled_processes": len(fds), "remaining_pids": remaining,
                "status": "partial" if remaining else "hibernated"}
    finally:
        for fd in fds.values():
            os.close(fd)


def systemd_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'


def service(guard, action):
    unit = f"herdr-memory-guard-{guard.key}.service"
    if action == "start":
        folder = Path.home() / ".config/systemd/user"
        folder.mkdir(parents=True, exist_ok=True)
        argv = [sys.executable, str(Path(__file__).resolve()), "run", "--socket", guard.api.path,
                "--config-dir", str(guard.config_dir), "--state-dir", str(guard.state_dir)]
        content = "\n".join([
            "[Unit]", "Description=Herdr Memory Guard", "After=default.target", "", "[Service]", "Type=simple",
            "ExecStart=" + " ".join(systemd_quote(a) for a in argv), "Restart=on-failure", "RestartSec=30",
            "UMask=0077", "MemoryMax=128M", "CPUQuota=10%", "TasksMax=32", "NoNewPrivileges=true",
            "", "[Install]", "WantedBy=default.target", ""])
        (folder / unit).write_text(content)
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, timeout=15)
        subprocess.run(["systemctl", "--user", "enable", "--now", unit], check=True, timeout=15)
        # Pick up an updated installed checkout even when the service was already active.
        subprocess.run(["systemctl", "--user", "restart", unit], check=True, timeout=15)
    elif action == "stop":
        subprocess.run(["systemctl", "--user", "disable", "--now", unit], check=True, timeout=15)
    return {"service": unit, "action": action}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["once", "run", "start", "stop", "enable", "pause", "status", "protect", "unprotect", "resume", "prune-checkpoints"])
    parser.add_argument("--socket", default=os.environ.get("HERDR_SOCKET_PATH", "~/.config/herdr/herdr.sock"))
    parser.add_argument("--config-dir", default=os.environ.get("HERDR_PLUGIN_CONFIG_DIR", f"~/.config/herdr/plugins/config/{PLUGIN}"))
    parser.add_argument("--state-dir", default=os.environ.get("HERDR_PLUGIN_STATE_DIR", f"~/.local/state/herdr-memory-guard"))
    parser.add_argument("--pane", default=os.environ.get("HERDR_PANE_ID"))
    parser.add_argument("--apply", action="store_true", help="once only: enforce if config.enabled is true")
    parser.add_argument("--json", action="store_true", help="once only: print the full JSON report instead of the per-pane table")
    args = parser.parse_args()
    os.umask(0o077)
    guard = Guard(API(Path(args.socket).expanduser()), Path(args.config_dir).expanduser().resolve(), Path(args.state_dir).expanduser().resolve())
    if args.command in {"enable", "pause", "protect", "unprotect"}:
        with guard.locked():
            cfg = config_load(guard.config_path)
            if args.command in {"protect", "unprotect"}:
                if not args.pane:
                    raise GuardError("Provide --pane or invoke this action in a pane")
                panes = set(cfg["protected_panes"])
                (panes.add if args.command == "protect" else panes.discard)(args.pane)
                cfg["protected_panes"] = sorted(panes)
            else:
                cfg["enabled"] = args.command == "enable"
            atomic_json(guard.config_path, cfg)  # also drops deprecated settings
        print(json.dumps({"enabled": cfg["enabled"], "protected_panes": cfg["protected_panes"]}))
    elif args.command in {"start", "stop"}:
        print(json.dumps(service(guard, args.command)))
    elif args.command == "status":
        print(json.dumps({"config": config_load(guard.config_path), "state_dir": str(guard.directory), "latest": read_json(guard.status_path)}, indent=2))
    elif args.command == "resume":
        if not args.pane:
            raise GuardError("Provide --pane or invoke Resume in a hibernated pane")
        print(json.dumps(guard.resume(args.pane)))
    elif args.command == "once":
        report = guard.cycle(args.apply)
        print(json.dumps(report, indent=2) if args.json else render(report))
    elif args.command == "prune-checkpoints":
        # Dry run unless --apply; never removes successful hibernation records.
        print(json.dumps(guard.prune(args.apply), indent=2))
    else:
        # One daemon per session; one cycle lock also excludes manual invocations.
        with (guard.directory / "daemon.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            with contextlib.suppress(GuardError, OSError, ValueError):
                removed = guard.prune(apply=True)["remove"]
                if removed:
                    print(f"memory-guard: pruned {len(removed)} duplicate checkpoints of attempts that changed nothing", flush=True)
            while True:
                try:
                    if not plugin_enabled(guard.api):
                        return
                    report = guard.cycle(apply=True)
                    for a in report["actions"]:
                        who = "/".join(x for x in (a.get("project"), a.get("thread")) if x) or "unmanaged"
                        outcome = f"FAILED: {a['error']} (retry {a['retry']})" if "error" in a else a.get("status", "done")
                        print(f"memory-guard: {a['action']} {a['pane_id']} ({who}): {outcome}. Reason: {a.get('reason')}", flush=True)
                    interval = config_load(guard.config_path)["interval_seconds"]
                except Exception as exc:
                    # Fail closed; preserve the last good state and retry without any cleanup.
                    atomic_json(guard.status_path, {"at": time.time(), "error": str(exc)})
                    print(f"memory-guard: {exc}", file=sys.stderr, flush=True)
                    interval = 30
                time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except (GuardError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"memory-guard: {exc}", file=sys.stderr)
        sys.exit(1)

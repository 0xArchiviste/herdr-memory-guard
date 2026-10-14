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
    "idle_seconds": 7200,
    "pressure_idle_seconds": 1800,
    "quiet_seconds": 180,
    "resolved_shell_seconds": 86400,
    "max_actions_per_cycle": 3,
    "min_reclaim_mib": 64,
    "idle_budget_mib": 2048,
    "available_percent": 20,
    "recovery_percent": 25,
    "host_available_percent": 15,
    "host_recovery_percent": 20,
    "psi_some_avg10": 10,
    "max_cpu_percent": 1,
    "projects_root": "~/.herdr-projects",
    "managed_threads_only": True,
    "protect_coordinators": True,
    "protected_panes": [],
    "protected_projects": [],
    "checkpoint_limit_mib": 256,
    "max_checkpoints": 1000,
    "sample_windows_host": True,
}


class GuardError(RuntimeError):
    pass


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
    if not isinstance(overrides, dict) or set(overrides) - set(DEFAULTS):
        raise GuardError("Invalid config or unknown setting; automatic actions stopped")
    cfg = DEFAULTS | overrides
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
    if cfg["pressure_idle_seconds"] > cfg["idle_seconds"]:
        raise GuardError("pressure_idle_seconds must not exceed idle_seconds")
    if cfg["recovery_percent"] < cfg["available_percent"] or cfg["host_recovery_percent"] < cfg["host_available_percent"]:
        raise GuardError("Recovery thresholds must be at least the pressure thresholds")
    for key in ("max_actions_per_cycle", "max_checkpoints"):
        if type(cfg[key]) is not int:
            raise GuardError(f"{key} must be an integer")
    return cfg


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
            raise GuardError(f"Herdr {method} failed: {result.get('error', 'invalid response')}")
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
    records, coordinators = {}, set()
    root = Path(root).expanduser()
    for project in root.iterdir() if root.exists() else []:
        if not project.is_dir() or project.name.startswith("."):
            continue
        try:
            binding = read_json(project / ".state/coordinator.json")
            if binding.get("socket") != socket_path:
                continue
            if binding.get("pane_id"):
                coordinators.add(binding["pane_id"])
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
    return [pane.get("revision"), pane.get("state_change_seq"), pane.get("agent_status")]


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
    if pane.get("agent_status") not in SAFE_STATES:
        return "working, blocked, or unknown"
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


def pressure_level(memory, cfg, previous, idle_mib):
    reasons = []
    if memory["available_percent"] < cfg["recovery_percent" if previous else "available_percent"]:
        reasons.append("Linux available memory")
    host = memory.get("host_available_percent")
    if host is not None and host < cfg["host_recovery_percent" if previous else "host_available_percent"]:
        reasons.append("Windows available memory")
    if memory["psi_some_avg10"] >= cfg["psi_some_avg10"]:
        reasons.append("Linux memory stalls")
    if idle_mib > cfg["idle_budget_mib"]:
        reasons.append("idle agent memory budget")
    return reasons


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

    def _cycle(self, apply):
        cfg = config_load(self.config_path)
        now = time.time()
        server = self.api.server_identity()
        state = read_json(self.state_path)
        if state.get("server") != server:
            state = {"server": server, "observations": {}}
        snapshot = self.api.call("session.snapshot")["snapshot"]
        table = process_table()
        records, coordinators = project_records(cfg["projects_root"], self.api.path)
        memory = memory_sample(cfg, state)
        observations, candidates, skipped = {}, [], Counter()
        scopes = {}
        for pane in snapshot["panes"]:
            pid = pane["pane_id"]
            # Global focus is authoritative even if a PaneInfo omitted its flag.
            if pid == snapshot.get("focused_pane_id"):
                pane = pane | {"focused": True}
            record = records.get(pid)
            reason = protection(pane, record, coordinators, cfg)
            shell_candidate = (record and record.get("status") == "resolved" and not pane.get("agent")
                               and not pane.get("focused") and pid not in cfg["protected_panes"]
                               and record["project"] not in cfg["protected_projects"] and pid not in coordinators)
            if reason and not shell_candidate:
                skipped[reason] += 1
                continue
            try:
                info = self.api.call("pane.process_info", pane_id=pid)["process_info"]
            except (GuardError, OSError):
                skipped["process info unavailable"] += 1
                continue
            if shell_candidate:
                shell = table.get(info.get("shell_pid"))
                tree = descendants(shell.pid, table) if shell else {}
                if not shell or shell.name not in SHELLS or info.get("foreground_process_group_id") != shell.pgrp or len(tree) != 1:
                    skipped["resolved pane has running processes"] += 1
                    continue
                scope, roots, action = tree, [shell.pid], "close-resolved-shell"
            else:
                scope, roots = process_scope(info, table, pane.get("agent"))
                action = "hibernate"
                if not scope:
                    skipped["unverified foreground agent"] += 1
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
                         "quiet_seconds": int(now - observation["quiet_since"]), "ready": False}
            candidates.append(candidate)
            scopes[pid] = (pane, record, scope, roots, info, observation)
        idle_mib = sum(c["rss_mib"] + c["swap_mib"] for c in candidates if c["action"] == "hibernate")
        pressure = pressure_level(memory, cfg, state.get("pressure", False), idle_mib)
        for c in candidates:
            ttl = cfg["resolved_shell_seconds"] if c["action"] == "close-resolved-shell" else cfg["pressure_idle_seconds" if pressure else "idle_seconds"]
            c["ready"] = (c["idle_seconds"] >= ttl and c["quiet_seconds"] >= cfg["quiet_seconds"]
                          and (c["action"] == "close-resolved-shell" or c["rss_mib"] + c["swap_mib"] >= cfg["min_reclaim_mib"]))
        candidates.sort(key=lambda c: (c["ready"], c["action"] == "hibernate", c["rss_mib"] + c["swap_mib"], c["idle_seconds"]), reverse=True)
        state.update(observations=observations, pressure=bool(pressure))
        atomic_json(self.state_path, state)
        report = {"at": now, "enabled": cfg["enabled"], "apply": apply, "server": server,
                  "panes": len(snapshot["panes"]), "agents": len(snapshot.get("agents", [])),
                  "memory": memory, "idle_agent_mib": round(idle_mib), "pressure": pressure,
                  "protected": dict(skipped), "candidates": candidates, "actions": []}
        if apply and cfg["enabled"]:
            for c in [c for c in candidates if c["ready"]][:cfg["max_actions_per_cycle"]]:
                try:
                    result = self.reclaim(c, scopes[c["pane_id"]], cfg, coordinators, server)
                    report["actions"].append(result)
                    # Treat ambiguous partial actions as consumed, never retry blindly.
                    state["observations"].pop(c["pane_id"], None)
                except (GuardError, OSError, ValueError) as exc:
                    report["actions"].append({"pane_id": c["pane_id"], "error": str(exc)})
        atomic_json(self.state_path, state)
        atomic_json(self.status_path, report)
        return report

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
        current = self.api.call("pane.get", pane_id=pid)["pane"]
        if identity(current) != identity(pane) or activity(current) != activity(pane):
            raise GuardError("Pane became active or its occupant changed")
        if current.get("focused") or pid in latest_cfg["protected_panes"] or (record or {}).get("project") in latest_cfg["protected_projects"]:
            raise GuardError("Pane is now focused or protected")
        if candidate["action"] == "hibernate":
            reason = protection(current, record, latest_coordinators, latest_cfg)
            if reason:
                raise GuardError(reason)
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
        if any(fresh_scope[p.pid].ticks != p.ticks for p in scope.values()):
            raise GuardError("Processes became CPU-active during final validation")
        checkpoint = self.checkpoint(candidate, pane, record, scope, server, cfg)
        # Check again after checkpoint I/O and reading terminal output.
        current = self.api.call("pane.get", pane_id=pid)["pane"]
        if current.get("focused") or identity(current) != identity(pane) or activity(current) != activity(pane):
            raise GuardError("Pane changed while checkpointing; checkpoint retained")
        if candidate["action"] == "close-resolved-shell":
            # Never close a shell with even one background descendant.
            if len(descendants(info["shell_pid"], process_table())) != 1:
                raise GuardError("Shell acquired a background job")
            self.api.call("pane.close", pane_id=pid)
            result = {"pane_id": pid, "action": candidate["action"], "checkpoint": str(checkpoint)}
        else:
            def validate_before_signal():
                final = self.api.call("pane.get", pane_id=pid)["pane"]
                if final.get("focused") or identity(final) != identity(pane) or activity(final) != activity(pane):
                    raise GuardError("Pane changed before signaling")
                if not config_load(self.config_path)["enabled"]:
                    raise GuardError("Automatic reclamation is paused")
            result = terminate_scope(scope, roots, validate=validate_before_signal)
            result.update(pane_id=pid, action="hibernate", checkpoint=str(checkpoint),
                          estimated_rss_mib=candidate["rss_mib"], estimated_swap_mib=candidate["swap_mib"])
        saved = read_json(checkpoint)
        saved["outcome"] = result
        atomic_json(checkpoint, saved)
        self.audit(result)
        return result

    def checkpoint(self, candidate, pane, record, scope, server, cfg):
        directory = self.directory / "checkpoints"
        directory.mkdir(exist_ok=True, mode=0o700)
        files = list(directory.glob("*.json"))
        if len(files) >= cfg["max_checkpoints"] or sum(f.stat().st_size for f in files) >= cfg["checkpoint_limit_mib"] * MIB:
            raise GuardError("Checkpoint budget reached; preserve existing recovery records and stop reclaiming")
        output = self.api.call("pane.read", pane_id=pane["pane_id"], source="recent_unwrapped", lines=200, strip_ansi=True)
        data = {"at": time.time(), "server": server, "socket": self.api.path,
                "pane": pane, "thread": record, "terminal_output": output,
                "processes": [dataclasses.asdict(p) for p in scope.values()], "decision": candidate}
        if candidate["action"] == "hibernate":
            data["resume_args"] = resume_args(pane["agent"], pane["agent_session"])
        if sum(f.stat().st_size for f in files) + len(json.dumps(data, ensure_ascii=False).encode()) > cfg["checkpoint_limit_mib"] * MIB:
            raise GuardError("Checkpoint budget would be exceeded; automatic action stopped")
        path = directory / f"{time.time_ns()}-{pane['pane_id'].replace(':', '-')}.json"
        atomic_json(path, data)
        return path

    def audit(self, result):
        path = self.directory / "audit.jsonl"
        if path.exists() and path.stat().st_size > 2 * MIB:
            os.replace(path, path.with_suffix(".previous.jsonl"))
        with path.open("a") as out:
            out.write(json.dumps({"at": time.time(), **result}) + "\n")

    def resume(self, pane_id):
        with self.locked():
            choices = sorted((self.directory / "checkpoints").glob("*.json"), reverse=True)
            saved = next((read_json(p) for p in choices if read_json(p).get("pane", {}).get("pane_id") == pane_id and read_json(p).get("outcome", {}).get("action") == "hibernate"), None)
            if not saved:
                raise GuardError("No successful hibernation checkpoint for this pane")
            pane = self.api.call("pane.get", pane_id=pane_id)["pane"]
            original = saved["pane"]
            if self.api.server_identity() != saved["server"] or pane.get("terminal_id") != original.get("terminal_id"):
                raise GuardError("Pane/server was replaced; use the checkpoint's native resume arguments in the original working directory")
            if pane.get("agent"):
                raise GuardError("Pane already has an agent")
            info = self.api.call("pane.process_info", pane_id=pane_id)["process_info"]
            table = process_table()
            shell = table.get(info.get("shell_pid"))
            if not shell or shell.name not in SHELLS or shell.pgrp != info.get("foreground_process_group_id") or len(descendants(shell.pid, table)) != 1:
                raise GuardError("Pane is not an empty interactive shell")
            # Native CLI validates prompt readiness and refuses a busy pane.
            kind = original["agent"]
            args = resume_args(kind, original["agent_session"])
            name = original.get("name") or f"mg-{hashlib.sha256(pane_id.encode()).hexdigest()[:12]}"
            result = self.api.call("agent.start", pane_id=pane_id, kind=kind, name=name, args=args, timeout_ms=8000)
            self.audit({"action": "resume", "pane_id": pane_id})
            return result


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
    parser.add_argument("command", choices=["once", "run", "start", "stop", "enable", "pause", "status", "protect", "unprotect", "resume"])
    parser.add_argument("--socket", default=os.environ.get("HERDR_SOCKET_PATH", "~/.config/herdr/herdr.sock"))
    parser.add_argument("--config-dir", default=os.environ.get("HERDR_PLUGIN_CONFIG_DIR", f"~/.config/herdr/plugins/config/{PLUGIN}"))
    parser.add_argument("--state-dir", default=os.environ.get("HERDR_PLUGIN_STATE_DIR", f"~/.local/state/herdr-memory-guard"))
    parser.add_argument("--pane", default=os.environ.get("HERDR_PANE_ID"))
    parser.add_argument("--apply", action="store_true", help="once only: enforce if config.enabled is true")
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
            atomic_json(guard.config_path, cfg)
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
        print(json.dumps(guard.cycle(args.apply), indent=2))
    else:
        # One daemon per session; one cycle lock also excludes manual invocations.
        with (guard.directory / "daemon.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return
            while True:
                try:
                    if not plugin_enabled(guard.api):
                        return
                    report = guard.cycle(apply=True)
                    if report["actions"]:
                        print(json.dumps({"actions": report["actions"]}), flush=True)
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

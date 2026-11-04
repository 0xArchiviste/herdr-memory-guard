import copy
import dataclasses
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import guard as g


def pane(**changes):
    return dict(pane_id="w1:p2", terminal_id="term_test", agent="claude", agent_status="idle",
                focused=False, revision=20, state_change_seq=3, name="worker",
                agent_session={"kind": "id", "agent": "claude", "value": "12345678-abcd-1234"},
                tokens={"hp_group": "demo!1!2!t-0001"}) | changes


def proc(pid, ppid, pgrp, name, start=1, ticks=10):
    return g.Proc(pid, ppid, pgrp, 100, start, ticks, 100 * g.MIB, 20 * g.MIB, name)


class PolicyTests(unittest.TestCase):
    def test_installed_plugin_response_and_disable(self):
        api = Mock()
        api.call.return_value = {"type": "plugin_list", "plugins": [{"plugin_id": g.PLUGIN, "enabled": True}]}
        self.assertTrue(g.plugin_enabled(api))
        api.call.return_value["plugins"][0]["enabled"] = False
        self.assertFalse(g.plugin_enabled(api))
        api.call.return_value = {"plugins": []}
        self.assertFalse(g.plugin_enabled(api))

    def test_active_unknown_and_blocked_never_eligible(self):
        for state in ["working", "blocked", "unknown", None]:
            self.assertTrue(g.protection(pane(agent_status=state), {}, set(), g.DEFAULTS))

    def test_focus_coordinator_and_pins(self):
        for p in [pane(focused=True), pane(tokens={"hp_group": "demo!0!w1:p2"}), pane(name="hpc-demo")]:
            self.assertTrue(g.protection(p, {}, set(), g.DEFAULTS))
        cfg = g.DEFAULTS | {"protected_panes": ["w1:p2"]}
        self.assertEqual(g.protection(pane(), {}, set(), cfg), "pinned")
        self.assertEqual(g.protection(pane(), {}, {"w1:p2"}, g.DEFAULTS), "coordinator")

    def test_unmanaged_and_pending_threads_are_protected(self):
        self.assertEqual(g.protection(pane(), None, set(), g.DEFAULTS), "unmanaged")
        self.assertTrue(g.protection(pane(), {"prompt_pending": True}, set(), g.DEFAULTS))
        self.assertTrue(g.protection(pane(), {"brief_stuck": True}, set(), g.DEFAULTS))

    def test_session_required_and_checked(self):
        for session in [{}, {"kind": "path", "value": "secret"}, {"kind": "id", "agent": "codex", "value": "12345678"}, {"kind": "id", "agent": "claude", "value": "--bad;cmd"}]:
            with self.assertRaises(g.GuardError):
                g.resume_args("claude", session)
        self.assertEqual(g.resume_args("codex", {"agent": "codex", "kind": "id", "value": "12345678"}), ["resume", "12345678"])
        self.assertEqual(g.resume_args("claude", {"agent": "claude", "kind": "id", "value": "12345678"}), ["--resume", "12345678"])
        self.assertEqual(g.resume_args("opencode", {"agent": "opencode", "kind": "id", "value": "ses_12345678"}), ["--session", "ses_12345678"])
        self.assertEqual(g.native_resume_command("claude", ["--resume", "12345678"], "/work/a b"), "cd '/work/a b' && claude --resume 12345678")

    def test_pressure_uses_available_and_hysteresis(self):
        memory = {"available_percent": 22, "available_mib": 22000, "host_available_percent": 50, "psi_some_avg10": 0}
        self.assertFalse(g.pressure_level(memory, g.DEFAULTS, False))
        self.assertTrue(g.pressure_level(memory, g.DEFAULTS, True))
        self.assertTrue(g.pressure_level(memory | {"host_available_percent": 10}, g.DEFAULTS, False))
        self.assertTrue(g.pressure_level(memory | {"psi_some_avg10": 30}, g.DEFAULTS, False))

    def test_pressure_reasons_name_threshold_and_numbers(self):
        memory = {"available_percent": 9.5, "available_mib": 9000, "host_available_percent": 8.25, "psi_some_avg10": 12.5}
        reasons = g.pressure_level(memory, g.DEFAULTS, False)
        self.assertEqual(len(reasons), 3)
        self.assertIn("9.5%", reasons[0])
        self.assertIn("9000 MiB", reasons[0])
        self.assertIn("20%", reasons[0])
        self.assertIn("8.2%", reasons[1])
        self.assertIn("12.5", reasons[2])
        headroom = g.headroom(memory | {"available_percent": 60, "host_available_percent": 50, "psi_some_avg10": 0}, g.DEFAULTS)
        self.assertIn("60", headroom)

    def test_idle_budget_is_never_pressure_and_old_keys_are_ignored(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            g.atomic_json(path, {"idle_seconds": 7200, "idle_budget_mib": 2048})
            cfg = g.config_load(path)
            self.assertNotIn("idle_budget_mib", cfg)
            self.assertNotIn("idle_seconds", cfg)
            self.assertEqual(g.ignored_settings(path), ["idle_budget_mib", "idle_seconds"])
        # Plenty of headroom: no pressure, however much idle agents hold.
        memory = {"available_percent": 28.9, "available_mib": 20908, "host_available_percent": 25.3, "psi_some_avg10": 0.7}
        self.assertEqual(g.pressure_level(memory, g.DEFAULTS, False), [])


class ThreadHoldTests(unittest.TestCase):
    record = {"project": "demo", "id": "t-0001", "status": "open", "report_hash": "", "acked_report_hash": "",
              "pr_state": "", "last_state_change": "2000-01-01T00:00:00Z", "launched_at": "2000-01-01T00:00:00Z"}

    def hold(self, now=2e9, record=None, **live):
        live = {"group_token": "idle", "status": "open", "activity": ""} | live
        return g.thread_hold(record or self.record, live, now, g.DEFAULTS)

    def test_idle_acked_thread_is_eligible(self):
        self.assertEqual(self.hold(), ("", ""))

    def test_waiting_on_user_groups_are_protected(self):
        for group in ["waiting-on-you", "ready-for-review", "landing"]:
            rule, reason = self.hold(group_token=group)
            self.assertEqual(rule, "waiting on the user", group)
            self.assertIn(group.replace("-", " ").split(" (")[0], reason.replace("-", " "))
        self.assertEqual(self.hold(group_token="working")[0], "thread is working")

    def test_unacked_report_open_pr_and_question_are_waiting(self):
        self.assertIn("unacknowledged report", self.hold(report_hash="abc", acked_report_hash="")[1])
        self.assertIn("pull request", self.hold(pr_state="OPEN")[1])
        self.assertIn("waiting", self.hold(activity="Waiting for you")[1])
        self.assertEqual(self.hold(group_token="resolved", status="resolved", report_hash="abc"), ("", ""))

    def test_unknown_state_fails_closed(self):
        self.assertTrue(g.thread_hold(self.record, None, 2e9, g.DEFAULTS)[1])
        self.assertTrue(self.hold(group_token="something-new")[1])

    def test_recent_work_is_protected(self):
        now = g.parse_time("2026-01-01T12:00:00Z")
        rule, reason = self.hold(now, last_state_change="2026-01-01T11:40:00Z")
        self.assertEqual(rule, "recently worked")
        self.assertIn("20m", reason)
        self.assertEqual(self.hold(now, last_state_change="2026-01-01T10:00:00Z"), ("", ""))
        self.assertEqual(self.hold(now, last_report_change="2026-01-01T11:59:00Z")[0], "recently worked")

    def test_thread_states_reads_cli_json_and_fails_closed(self):
        payload = json.dumps([{"id": "t-0001", "group_token": "idle", "pane_id": "w1:p2"}])
        done = subprocess.CompletedProcess([], 0, stdout=payload, stderr="")
        cfg = g.DEFAULTS | {"herdr_projects_bin": "/bin/true"}
        with patch.object(g.subprocess, "run", return_value=done) as run:
            states, errors = g.thread_states(cfg, {"demo"})
        self.assertEqual(states[("demo", "t-0001")]["group_token"], "idle")
        self.assertEqual(run.call_args.args[0][-4:], ["thread", "list", "demo", "--json"])
        with patch.object(g.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)):
            states, errors = g.thread_states(cfg, {"demo"})
        self.assertFalse(states)
        self.assertIn("demo", errors)


class CheckpointTests(unittest.TestCase):
    def write(self, folder, name, pane_id="w1:p2", outcome=None, action="hibernate", session="12345678"):
        data = {"pane": {"pane_id": pane_id, "terminal_id": "term", "agent_session": {"value": session}},
                "decision": {"action": action}}
        if outcome:
            data["outcome"] = outcome
        g.atomic_json(folder / name, data)

    def test_prune_removes_only_superseded_unsuccessful_duplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            for n in range(1, 6):
                self.write(folder, f"{n}-w9-p1.json", pane_id="w9:p1", action="close-resolved-shell")
            self.write(folder, "10-w1-p2.json", outcome={"action": "hibernate", "status": "hibernated"})
            self.write(folder, "11-w1-p2.json", outcome={"action": "hibernate", "status": "hibernated"})
            self.write(folder, "12-w1-p3.json", pane_id="w1:p3", outcome={"status": "aborted"})
            self.write(folder, "13-w1-p3.json", pane_id="w1:p3", outcome={"action": "hibernate", "status": "hibernated"})
            (folder / "14-corrupt.json").write_text("{")
            plan = g.prune_checkpoints(folder, apply=False)
            self.assertEqual(len(plan["remove"]), 5)
            self.assertTrue((folder / "1-w9-p1.json").exists())
            g.prune_checkpoints(folder, apply=True)
            left = sorted(p.name for p in folder.iterdir())
            self.assertEqual(left, ["10-w1-p2.json", "11-w1-p2.json", "13-w1-p3.json", "14-corrupt.json", "5-w9-p1.json"])


class InboxTests(unittest.TestCase):
    def test_inbox_item_matches_herdr_projects_format(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "demo"
            (project / ".state").mkdir(parents=True)
            (project / "PROJECT.md").write_text("+++\n+++\n")
            item = g.write_inbox(temp, "demo", "t-0001", "hibernated by Memory Guard", 'line one\nwith "quotes"')
            path = project / "inbox" / f"{item}.md"
            text = path.read_text()
            self.assertTrue(text.startswith("+++\n") and text.endswith("+++\n"))
            front = g.tomllib.loads(text[4:-4])
            self.assertEqual(front["id"], item)
            self.assertEqual(front["kind"], "memory-guard")
            self.assertEqual(front["subject"], "t-0001")
            self.assertEqual(front["summary"], 'line one with "quotes"')
            self.assertRegex(item, r"^\d{8}T\d{6}Z-memory-guard-t-0001-[A-Za-z0-9]+$")
            with self.assertRaises(g.GuardError):
                g.write_inbox(temp, "missing", "t-0001", "x", "y")

    def test_scope_excludes_shell_unrelated_process_and_background_sibling(self):
        table = {100: proc(100, 1, 100, "bash"), 101: proc(101, 100, 101, "claude"),
                 102: proc(102, 101, 102, "node"), 103: proc(103, 100, 103, "server"),
                 104: proc(104, 1, 101, "claude")}
        scope, roots = g.process_scope({"shell_pid": 100, "foreground_process_group_id": 101}, table, "claude")
        self.assertEqual(set(scope), {101, 102})
        self.assertEqual(roots, [101])

    def test_scope_refuses_shell_foreground_and_wrong_agent(self):
        table = {100: proc(100, 1, 100, "bash"), 101: proc(101, 100, 101, "vim")}
        for fg in [100, 101, 999]:
            self.assertEqual(g.process_scope({"shell_pid": 100, "foreground_process_group_id": fg}, table, "claude"), ({}, []))

    def test_invalid_config_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            for value in [{"enabled": "false"}, {"quiet_seconds": 0}, {"oops": True}, {"max_actions_per_cycle": 1.5}, {"available_percent": 101}, {"idle_budget_mib": float("nan")}, {"protected_panes": [123]}]:
                g.atomic_json(path, value)
                with self.assertRaises(g.GuardError):
                    g.config_load(path)

    def test_atomic_files_are_private(self):
        with tempfile.TemporaryDirectory() as temp:
            file = Path(temp) / "checkpoint.json"
            g.atomic_json(file, {"private": "session"})
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_project_binding_is_session_scoped(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "demo"
            (project / "threads").mkdir(parents=True)
            g.atomic_json(project / ".state/coordinator.json", {"socket": "/one.sock", "pane_id": "w1:p1"})
            (project / "threads/t-0001.toml").write_text('pane_id = "w1:p2"\nstatus = "open"\n')
            self.assertFalse(g.project_records(temp, "/two.sock")[0])
            records, coords = g.project_records(temp, "/one.sock")
            self.assertIn("w1:p2", records)
            self.assertEqual(coords, {"w1:p1"})


class CycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.api = Mock(path="/fake.sock")
        self.api.server_identity.return_value = "boot:1:1"
        self.pane = pane()
        self.info = {"shell_pid": 100, "foreground_process_group_id": 101}
        self.table = {100: proc(100, 1, 100, "bash"), 101: proc(101, 100, 101, "claude")}
        self.record = {"project": "demo", "id": "t-0001", "status": "open", "last_state": "idle",
                       "updated": "1970-01-01T00:00:01Z", "last_state_change": "1970-01-01T00:00:01Z"}
        self.api.call.side_effect = self.call
        self.screen = "saved terminal history"
        self.guard = g.Guard(self.api, Path(self.temp.name) / "cfg", Path(self.temp.name) / "state")
        self.projects = Path(self.temp.name) / "projects"
        (self.projects / "demo/.state").mkdir(parents=True)
        (self.projects / "demo/PROJECT.md").write_text("+++\n+++\n")
        self.cfg = g.DEFAULTS | {"enabled": True, "quiet_seconds": 30, "pressure_idle_seconds": 60,
                                 "projects_root": str(self.projects)}
        g.atomic_json(self.guard.config_path, self.cfg)
        # Default: genuine Linux memory pressure, so the other rules are what is under test.
        self.memory = {"available_percent": 5, "available_mib": 4000, "host_available_percent": 50, "psi_some_avg10": 0}
        self.live = {"id": "t-0001", "group_token": "idle", "status": "open", "activity": ""}
        self.coordinators = set()
        self.closed = []
        for target, value in [("process_table", lambda: self.table),
                              ("project_records", lambda *_: ({"w1:p2": self.record}, self.coordinators)),
                              ("memory_sample", lambda *_: dict(self.memory)),
                              ("thread_states", lambda *_: ({("demo", "t-0001"): dict(self.live)} if self.live else {}, {}))]:
            patcher = patch.object(g, target, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, method, **params):
        if method == "session.snapshot":
            return {"snapshot": {"panes": [copy.deepcopy(self.pane)], "agents": [copy.deepcopy(self.pane)] if self.pane.get("agent") else [], "focused_pane_id": "other"}}
        if method == "pane.process_info":
            return {"process_info": self.info.copy()}
        if method == "pane.get":
            return {"pane": copy.deepcopy(self.pane)}
        if method == "agent.get":
            return {"agent": copy.deepcopy(self.pane)}
        if method == "pane.read":
            return {"read": {"text": self.screen}}
        if method == "pane.close":
            self.closed.append(params["pane_id"])
            if getattr(self, "close_error", None):
                raise self.close_error
        if method == "agent.start":
            self.pane["agent"] = params["kind"]
        return {}

    def inbox(self):
        return [g.tomllib.loads(p.read_text()[4:-4]) for p in sorted((self.projects / "demo/inbox").glob("*.md"))]

    def decision(self, report, pane_id="w1:p2"):
        return next(d for d in report["decisions"] if d["pane_id"] == pane_id)

    # --- Rule: act only under genuine memory pressure ---------------------------

    def test_no_pressure_never_hibernates_however_long_idle(self):
        self.memory = {"available_percent": 28.9, "available_mib": 20908, "host_available_percent": 25.3, "psi_some_avg10": 0.7}
        self.cycle(1000)
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
            report = self.cycle(500000, True)
        terminate.assert_not_called()
        self.assertFalse(report["pressure"])
        d = self.decision(report)
        self.assertEqual(d["decision"], "watching")
        self.assertIn("no memory pressure", d["reason"])
        self.assertIn("28.9%", d["reason"])

    def test_pressure_action_logs_threshold_and_numbers(self):
        self.cycle(1000)
        with patch.object(g, "terminate_scope", return_value={"status": "hibernated"}):
            report = self.cycle(1031, True)
        action = report["actions"][0]
        self.assertIn("MemAvailable 5%", action["reason"])
        self.assertIn("below 20%", action["reason"])
        audit = [json.loads(l) for l in (self.guard.directory / "audit.jsonl").read_text().splitlines()]
        self.assertIn("below 20%", audit[-1]["reason"])
        self.assertEqual(g.read_json(action["checkpoint"])["reason"], action["reason"])

    # --- Rule: never stop coordinators, waiting threads, recent work -----------

    def test_waiting_on_user_thread_is_never_stopped(self):
        for group in ["ready-for-review", "waiting-on-you", "landing"]:
            self.live["group_token"] = group
            self.cycle(1000)
            with patch.object(g, "terminate_scope") as terminate:
                report = self.cycle(1031, True)
            terminate.assert_not_called()
            self.assertEqual(self.decision(report)["decision"], "protected")
            self.assertIn("waiting on the user", self.decision(report)["reason"])

    def test_done_agent_with_unacked_report_is_protected(self):
        self.pane["agent_status"] = "done"
        self.record.update(report_hash="abc", acked_report_hash="")
        self.cycle(1000)
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("unacknowledged report", self.decision(report)["reason"])

    def test_thread_state_unavailable_fails_closed(self):
        self.live = None
        self.cycle(1000)
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertEqual(self.decision(report)["decision"], "protected")

    def test_recently_worked_thread_is_protected(self):
        self.record["last_state_change"] = "1970-01-01T00:16:00Z"  # 960s
        self.cycle(1000)
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("recently worked", self.decision(report)["reason"])

    def test_coordinator_is_never_touched(self):
        self.coordinators.add("w1:p2")
        self.cycle(1000)
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertEqual(self.decision(report)["reason"], "coordinator")
        self.assertFalse(any(c.args[0] == "pane.process_info" for c in self.api.call.call_args_list))

    def test_thread_state_rechecked_at_mutation_boundary(self):
        self.cycle(1000)
        states = iter([({("demo", "t-0001"): dict(self.live)}, {}),
                       ({("demo", "t-0001"): self.live | {"group_token": "ready-for-review"}}, {})])
        with patch.object(g, "thread_states", side_effect=lambda *_: next(states)), patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("waiting on the user", report["actions"][0]["error"])

    # --- Rule: no retry loops ---------------------------------------------------

    def resolved_shell(self):
        self.pane = pane(agent=None, agent_status="unknown", agent_session=None)
        self.record["status"] = "resolved"
        self.info["foreground_process_group_id"] = 100
        del self.table[101]

    def test_refused_close_is_not_retried_until_state_changes(self):
        self.resolved_shell()
        self.close_error = g.GuardError("Herdr pane.close failed: confirmation_required", permanent=True)
        self.cycle(100000)
        first = self.cycle(100031, True)
        self.assertIn("error", first["actions"][0])
        for t in range(100062, 100062 + 30 * 40, 30):
            report = self.cycle(t, True)
            self.assertFalse(report["actions"])
        self.assertEqual(self.closed, ["w1:p2"])
        self.assertEqual(self.decision(report)["decision"], "backoff")
        self.assertIn("until the pane or thread changes", self.decision(report)["reason"])
        checkpoints = list((self.guard.directory / "checkpoints").glob("*.json"))
        self.assertEqual(len(checkpoints), 1)
        self.assertEqual(g.read_json(checkpoints[0])["outcome"]["status"], "aborted")
        # A changed pane occupant clears the give-up.
        self.pane["terminal_id"] = "term_new"
        self.assertNotEqual(self.decision(self.cycle(200000))["decision"], "backoff")

    def test_transient_failure_backs_off_exponentially_and_reuses_checkpoint(self):
        self.cycle(1000)
        with patch.object(g, "terminate_scope", side_effect=g.GuardError("Pane changed before signaling")) as terminate:
            self.cycle(1031, True)
            self.assertEqual(terminate.call_count, 1)
            failures = g.read_json(self.guard.state_path)["failures"]["w1:p2"]
            self.assertEqual(failures["next_at"] - 1031, 300)
            for t in range(1062, 1031 + 300, 30):
                self.cycle(t, True)
            self.assertEqual(terminate.call_count, 1)
            self.cycle(1031 + 301, True)
            self.cycle(1031 + 332, True)
            self.assertEqual(terminate.call_count, 2)
            failures = g.read_json(self.guard.state_path)["failures"]["w1:p2"]
            self.assertEqual(failures["count"], 2)
            self.assertEqual(round(failures["next_at"] - failures["at"]), 600)
        self.assertEqual(len(list((self.guard.directory / "checkpoints").glob("*.json"))), 1)

    # --- Rule: coordinators keep context ----------------------------------------

    def test_hibernation_notifies_coordinator_with_full_context(self):
        self.cycle(1000)
        with patch.object(g, "terminate_scope", return_value={"status": "hibernated"}):
            report = self.cycle(1031, True)
        action = report["actions"][0]
        items = self.inbox()
        self.assertEqual(len(items), 1)
        summary = items[0]["summary"]
        self.assertEqual(items[0]["subject"], "t-0001")
        self.assertIn("t-0001", summary)
        self.assertIn("below 20%", summary)
        self.assertIn(action["checkpoint"], summary)
        self.assertIn("resume --pane w1:p2", summary)
        self.assertIn("claude --resume 12345678-abcd-1234", summary)
        registry = g.read_json(self.guard.directory / "hibernated.json")["hibernated"]
        self.assertEqual(registry["w1:p2"]["thread"], "t-0001")
        self.assertEqual(registry["w1:p2"]["checkpoint"], action["checkpoint"])
        self.assertIn("resume --pane w1:p2", registry["w1:p2"]["resume_command"])

    def test_resume_restores_session_verifies_and_notifies(self):
        self.cycle(1000)
        with patch.object(g, "terminate_scope", return_value={"status": "hibernated"}):
            self.cycle(1031, True)
        self.pane = self.pane | {"agent": None}
        del self.table[101]
        self.info["foreground_process_group_id"] = 100
        result = self.guard.resume("w1:p2", verify_seconds=0)
        self.api.call.assert_any_call("agent.start", pane_id="w1:p2", kind="claude", name="worker",
                                      args=["--resume", "12345678-abcd-1234"], timeout_ms=8000)
        self.assertTrue(result["session_verified"])
        self.assertEqual(result["session_id"], "12345678-abcd-1234")
        self.assertFalse(g.read_json(self.guard.directory / "hibernated.json")["hibernated"])
        self.assertIn("resumed", self.inbox()[-1]["event"])
        self.assertIn("verified", self.inbox()[-1]["summary"])

    def test_resume_reports_unverified_session(self):
        self.prepare_resume()
        original = self.call
        self.api.call.side_effect = lambda m, **kw: ({"agent": self.pane | {"agent_session": {"kind": "id", "agent": "claude", "value": "other-session-1"}}}
                                                      if m == "agent.get" else original(m, **kw))
        self.assertFalse(self.guard.resume("w1:p2", verify_seconds=0)["session_verified"])

    # --- Dry run explains every pane --------------------------------------------

    def test_dry_run_explains_every_pane(self):
        report = self.cycle(1000)
        self.assertEqual(len(report["decisions"]), report["panes"])
        self.assertTrue(all(d["decision"] and d["reason"] for d in report["decisions"]))
        text = g.render(report)
        self.assertIn("w1:p2", text)
        self.assertIn("dry run", text)
        self.assertIn(self.decision(report)["reason"], text)

    def cycle(self, now, apply=False):
        with patch.object(g.time, "time", return_value=now):
            return self.guard.cycle(apply)

    def test_requires_live_quiet_observations_before_hibernation(self):
        self.assertFalse(self.cycle(1000)["candidates"][0]["ready"])
        with patch.object(g, "terminate_scope", return_value={"status": "hibernated"}) as terminate:
            report = self.cycle(1031, True)
        terminate.assert_called_once()
        self.assertEqual(report["actions"][0]["action"], "hibernate")
        saved = g.read_json(report["actions"][0]["checkpoint"])
        self.assertEqual(saved["resume_args"], ["--resume", "12345678-abcd-1234"])
        self.assertIn("terminal_output", saved)

    def test_dry_run_and_paused_never_signal(self):
        self.cycle(1000)
        with patch.object(g, "terminate_scope") as terminate:
            self.assertTrue(self.cycle(1031)["candidates"][0]["ready"])
            g.atomic_json(self.guard.config_path, self.cfg | {"enabled": False})
            self.cycle(1062, True)
        terminate.assert_not_called()

    def test_output_activity_resets_idle_and_quiet(self):
        self.cycle(1000)
        self.screen = "new output or draft"
        candidate = self.cycle(1031)["candidates"][0]
        self.assertEqual(candidate["quiet_seconds"], 0)
        self.assertEqual(candidate["idle_seconds"], 0)

    def test_metadata_revision_does_not_reset_idle(self):
        self.cycle(1000)
        self.pane["revision"] += 1
        self.assertTrue(self.cycle(1031)["candidates"][0]["ready"])

    def test_agent_sequence_change_resets_idle(self):
        self.cycle(1000)
        self.pane["state_change_seq"] += 1
        self.assertFalse(self.cycle(1031)["candidates"][0]["ready"])

    def test_cpu_activity_resets_quiet(self):
        self.cycle(1000)
        self.table[101] = dataclasses.replace(self.table[101], ticks=20000)
        self.assertFalse(self.cycle(1031)["candidates"][0]["ready"])

    def test_missing_observation_or_restart_requires_new_quiet_window(self):
        self.cycle(1000)
        self.assertFalse(self.cycle(2000)["candidates"][0]["ready"])
        self.api.server_identity.return_value = "boot:2:2"
        self.assertFalse(self.cycle(2031)["candidates"][0]["ready"])

    def test_replaced_process_requires_new_observation(self):
        self.cycle(1000)
        self.table[101] = dataclasses.replace(self.table[101], start=2)
        self.assertFalse(self.cycle(1031)["candidates"][0]["ready"])

    def test_checkpoint_failure_prevents_signal(self):
        self.cycle(1000)
        with patch.object(self.guard, "checkpoint", side_effect=OSError("disk full")), patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("disk full", report["actions"][0]["error"])

    def test_final_cpu_burst_prevents_signal(self):
        self.cycle(1000)
        fresh = self.table | {101: dataclasses.replace(self.table[101], ticks=10000)}
        with patch.object(g, "process_table", side_effect=[self.table, fresh]), patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("CPU-active", report["actions"][0]["error"])

    def test_one_scheduler_tick_does_not_block_idle_reclamation(self):
        self.cycle(1000)
        fresh = self.table | {101: dataclasses.replace(self.table[101], ticks=11)}
        with patch.object(g, "process_table", side_effect=[self.table, fresh]), patch.object(g, "terminate_scope", return_value={"status": "hibernated"}) as terminate:
            report = self.cycle(1031, True)
        terminate.assert_called_once()
        self.assertEqual(report["actions"][0]["action"], "hibernate")

    def test_focus_race_aborts(self):
        self.cycle(1000)
        original = self.call
        def raced(method, **params):
            if method == "pane.get":
                return {"pane": self.pane | {"focused": True}}
            return original(method, **params)
        self.api.call.side_effect = raced
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("focused", report["actions"][0]["error"])

    def test_busy_state_race_aborts(self):
        self.cycle(1000)
        original = self.call
        self.api.call.side_effect = lambda method, **kw: {"pane": self.pane | {"agent_status": "working"}} if method == "pane.get" else original(method, **kw)
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertIn("active", report["actions"][0]["error"])
        self.assertNotIn("w1:p2", g.read_json(self.guard.state_path)["observations"])

    def test_resolved_shell_with_background_child_is_not_closed(self):
        self.pane = pane(agent=None, agent_status="unknown", agent_session=None)
        self.record["status"] = "resolved"
        self.info["foreground_process_group_id"] = 100
        self.assertFalse(self.cycle(1000)["candidates"])

    def test_only_old_empty_resolved_shell_is_closed(self):
        self.pane = pane(agent=None, agent_status="unknown", agent_session=None)
        self.record["status"] = "resolved"
        self.info["foreground_process_group_id"] = 100
        del self.table[101]
        self.cycle(100000)
        report = self.cycle(100031, True)
        self.assertEqual(report["actions"][0]["action"], "close-resolved-shell")
        self.api.call.assert_any_call("pane.close", pane_id="w1:p2")

    def test_checkpoint_budget_stops_cleanup_without_deleting_history(self):
        self.cycle(1000)
        g.atomic_json(self.guard.config_path, self.cfg | {"max_checkpoints": 1})
        checkpoints = self.guard.directory / "checkpoints"
        g.atomic_json(checkpoints / "old.json", {"recovery": True})
        with patch.object(g, "terminate_scope") as terminate:
            report = self.cycle(1031, True)
        terminate.assert_not_called()
        self.assertTrue((checkpoints / "old.json").exists())
        self.assertIn("budget", report["actions"][0]["error"])

    def prepare_resume(self):
        original = self.pane | {"cwd": "/example/worktree"}
        g.atomic_json(self.guard.directory / "checkpoints/123-w1-p2.json", {
            "pane": original, "server": "boot:1:1", "outcome": {"action": "hibernate"}})
        self.pane = original | {"agent": None}
        del self.table[101]
        self.info["foreground_process_group_id"] = 100

    def test_resume_uses_native_session_without_prompt(self):
        self.prepare_resume()
        self.guard.resume("w1:p2")
        self.api.call.assert_any_call("agent.start", pane_id="w1:p2", kind="claude", name="worker",
                                      args=["--resume", "12345678-abcd-1234"], timeout_ms=8000)
        self.assertFalse(any(c.args[0] == "agent.prompt" for c in self.api.call.call_args_list))

    def test_resume_refuses_replaced_server(self):
        self.prepare_resume()
        self.api.server_identity.return_value = "boot:2:2"
        with self.assertRaisesRegex(g.GuardError, "replaced"):
            self.guard.resume("w1:p2")

    def test_resume_refuses_another_agent_or_busy_shell(self):
        self.prepare_resume()
        self.pane["agent"] = "claude"
        with self.assertRaisesRegex(g.GuardError, "already"):
            self.guard.resume("w1:p2")
        self.pane["agent"] = None
        self.table[101] = proc(101, 100, 101, "vim")
        with self.assertRaisesRegex(g.GuardError, "empty interactive shell"):
            self.guard.resume("w1:p2")

    def test_resume_refuses_changed_worktree(self):
        self.prepare_resume()
        self.pane["cwd"] = "/another/worktree"
        with self.assertRaisesRegex(g.GuardError, "directory changed"):
            self.guard.resume("w1:p2")


class SignalTests(unittest.TestCase):
    def test_final_activity_validator_runs_before_signals(self):
        original = proc(100, 1, 100, "test")
        validate = Mock(side_effect=g.GuardError("became working"))
        with patch.object(g.os, "pidfd_open", return_value=99), patch.object(g.os, "close"), patch.object(g, "read_proc", return_value=original), patch.object(g.signal, "pidfd_send_signal") as send:
            with self.assertRaises(g.GuardError):
                g.terminate_scope({100: original}, [100], validate)
        validate.assert_called_once()
        send.assert_not_called()

    def test_pid_reuse_refused_before_any_signal(self):
        original = proc(100, 1, 100, "test", start=1)
        with patch.object(g.os, "pidfd_open", return_value=99), patch.object(g.os, "close"), patch.object(g, "read_proc", return_value=dataclasses.replace(original, start=2)), patch.object(g.signal, "pidfd_send_signal") as send:
            with self.assertRaises(g.GuardError):
                g.terminate_scope({100: original}, [100])
        send.assert_not_called()

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux pidfds required")
    def test_real_term_only_reaps_owned_test_process_tree(self):
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print(p.pid,flush=True); time.sleep(60)"
        parent = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, text=True, start_new_session=True)
        child_pid = int(parent.stdout.readline())
        try:
            table = g.process_table()
            scope = g.descendants(parent.pid, table)
            self.assertIn(child_pid, scope)
            result = g.terminate_scope(scope, [parent.pid])
            self.assertEqual(result["status"], "hibernated")
            self.assertFalse(g.read_proc(child_pid))
            self.assertIsNotNone(g.read_proc(os.getpid()))
        finally:
            if parent.poll() is None:
                parent.terminate()
            parent.wait(timeout=5)
            parent.stdout.close()
            if g.read_proc(child_pid):
                os.kill(child_pid, 15)


if __name__ == "__main__":
    unittest.main()

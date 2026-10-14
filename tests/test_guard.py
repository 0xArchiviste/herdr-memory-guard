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

    def test_pressure_uses_available_and_hysteresis(self):
        memory = {"available_percent": 22, "host_available_percent": 50, "psi_some_avg10": 0}
        self.assertFalse(g.pressure_level(memory, g.DEFAULTS, False, 100))
        self.assertTrue(g.pressure_level(memory, g.DEFAULTS, True, 100))
        self.assertTrue(g.pressure_level(memory | {"host_available_percent": 10}, g.DEFAULTS, False, 100))
        self.assertTrue(g.pressure_level(memory, g.DEFAULTS, False, 3000))

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
        self.cfg = g.DEFAULTS | {"enabled": True, "quiet_seconds": 30, "idle_seconds": 120, "pressure_idle_seconds": 60}
        g.atomic_json(self.guard.config_path, self.cfg)
        for target, value in [("process_table", lambda: self.table), ("project_records", lambda *_: ({"w1:p2": self.record}, set())),
                              ("memory_sample", lambda *_: {"available_percent": 80, "host_available_percent": 50, "psi_some_avg10": 0})]:
            patcher = patch.object(g, target, side_effect=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, method, **params):
        if method == "session.snapshot":
            return {"snapshot": {"panes": [copy.deepcopy(self.pane)], "agents": [copy.deepcopy(self.pane)], "focused_pane_id": "other"}}
        if method == "pane.process_info":
            return {"process_info": self.info.copy()}
        if method == "pane.get":
            return {"pane": copy.deepcopy(self.pane)}
        if method == "agent.get":
            return {"agent": copy.deepcopy(self.pane)}
        if method == "pane.read":
            return {"read": {"text": self.screen}}
        return {}

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

"""Exercise the real restore transaction with temporary files and fake services."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def load(path):
    source = Path(path).read_text(encoding="utf-8")
    code = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    ns = {"__name__": "codex_transaction_review"}
    exec(compile(code, str(path), "exec"), ns)
    return ns["execute_restore_transaction"]


def exercise(transaction, scenario, tcp=False):
    with tempfile.TemporaryDirectory(prefix="codex-real-restore-test-") as temporary:
        base = Path(temporary)
        dest = base / "destination"
        stage = base / "stage"
        previous = base / "previous"
        original = {
            "/etc/hy2-node/config.json": b"ORIGINAL_CONFIG",
            "/etc/nginx/sites-available/default": b"ORIGINAL_NGINX",
            "/var/lib/cloudflare-warp/reg.json": b"ORIGINAL_WARP",
        }
        if tcp:
            original.update({'/etc/hy2-tcp/config.json': b'ORIGINAL_TCP_CONFIG',
                             '/etc/hy2-tcp/connection.json': b'ORIGINAL_TCP_CONNECTION',
                             '/etc/systemd/system/hy2-tcp.service': b'ORIGINAL_TCP_SERVICE'})
        introduced = "/etc/hy2-node/introduced.json"
        entries = []
        for name, content in {**original, introduced: b"NEW_ONLY"}.items():
            new = stage / ("files" + name)
            new.parent.mkdir(parents=True, exist_ok=True)
            new.write_bytes(b"REPLACEMENT_" + content)
            entries.append({"path": name, "archive_path": "files" + name, "type": "file", "mode": "0600"})
            if name in original:
                old = dest / name.lstrip("/")
                old.parent.mkdir(parents=True, exist_ok=True)
                old.write_bytes(content)
        link_name = "/etc/nginx/sites-enabled/default"
        live_link = dest / link_name.lstrip("/")
        live_link.parent.mkdir(parents=True)
        live_link.symlink_to("../sites-available/default")
        entries.append({"path": link_name, "archive_path": "files" + link_name,
                        "type": "symlink", "mode": "0777", "link_target": "../sites-available/default"})
        initial = {"hy2-node": True, "warp-svc": True, "nginx": scenario != "inactive-service"}
        if tcp: initial['hy2-tcp'] = True
        services = dict(initial)
        events = []

        def runner(*args, capture=False, check=True):
            events.append(args)
            rc = 0
            output = ""
            if args[0] == "systemctl" and len(args) >= 3:
                action, service = args[1], args[2]
                if action == "is-active":
                    rc = 0 if services.get(service, False) else 3
                    output = "active" if rc == 0 else "inactive"
                elif action in ("stop", "start", "restart"):
                    fail = ((scenario == "stop-failure" and action == "stop" and service == "warp-svc") or
                            (scenario == "rollback-failure" and action in ("start", "restart") and service == "warp-svc" and any(x == ("health",) for x in events)))
                    if fail:
                        rc = 1
                    else:
                        services[service] = action != "stop"
            if rc and check:
                raise subprocess.CalledProcessError(rc, list(args), output=output)
            return subprocess.CompletedProcess(list(args), rc, stdout=output, stderr="")

        def fail_health():
            events.append(("health",))
            runner("systemctl", "start", "hy2-node")
            runner("systemctl", "start", "nginx")
            raise RuntimeError("INJECTED_HEALTH_FAILURE")

        caught = None
        try:
            transaction(dest_root=dest, manifest={"files": entries}, staged_dir=stage,
                        pre_backup_dir=previous, runner=runner,
                        health_check=(lambda: None) if scenario == "stop-failure" else fail_health)
        except Exception as error:
            caught = error
        assert caught is not None, scenario + ": expected failure was swallowed"
        for name, expected in original.items():
            assert (dest / name.lstrip("/")).read_bytes() == expected, scenario + ": previous file changed: " + name
        assert not (dest / introduced.lstrip("/")).exists(), scenario + ": introduced file remains"
        assert live_link.is_symlink() and os.readlink(live_link) == "../sites-available/default"
        if scenario != "stop-failure":
            assert ("systemctl", "daemon-reload") in events, scenario + ": restored systemd units were not reloaded"
            if initial["nginx"]:
                assert ("systemctl", "restart", "nginx") in events, scenario + ": nginx kept the candidate config in memory"
        if scenario == "rollback-failure":
            message = str(caught).lower()
            assert "rollback" in message and ("failed" in message or "incomplete" in message), (
                "failed daemon recovery was falsely reported as rolled back: " + str(caught))
        else:
            assert services == initial, scenario + ": old daemon state was not restored: " + json.dumps(services)
        print("PASS: production restore transaction " + scenario + (' with TCP' if tcp else ' legacy HY2'))


if __name__ == "__main__":
    if os.name != "posix":
        raise SystemExit("Run this symlink/service simulation test on Linux.")
    function = load(sys.argv[1])
    for case in ("inactive-service", "stop-failure", "rollback-failure"):
        exercise(function, case)
        exercise(function, case, tcp=True)
    with tempfile.TemporaryDirectory(prefix='old-snapshot-refusal-') as td:
        root = Path(td)
        live = root / 'etc/hy2-tcp/config.json'
        live.parent.mkdir(parents=True)
        live.write_bytes(b'PRESERVE_EXISTING_TCP')
        events = []
        try:
            function(root, {'files': []}, root/'stage', root/'previous',
                     runner=lambda *args, **kwargs: events.append(args))
        except ValueError:
            pass
        else:
            raise AssertionError('old archive was allowed to leave an untracked TCP node')
        assert not events and live.read_bytes() == b'PRESERVE_EXISTING_TCP'
    print('PASS: old single-node snapshot refused before live mutation')
    print("ALL CODEX PRODUCTION TRANSACTION CHECKS PASSED")

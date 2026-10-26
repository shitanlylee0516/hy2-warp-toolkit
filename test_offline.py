#!/usr/bin/env python3
"""
Offline tests for HY2 installer, backup/restore tool, and archive verification.
Can be executed on any environment (Linux / Windows / macOS) without root, network, or external packages.
Usage:
    python3 test_offline.py
"""
import copy, hashlib, io, json, os, pathlib, re, shutil, sys, tarfile, tempfile, types

ROOT = pathlib.Path(__file__).parent.resolve()

def extract_embedded_python(script_path: pathlib.Path) -> str:
    content = script_path.read_text(encoding='utf-8')
    match = re.search(r"<<\s*['\"]?PY['\"]?\s*\n(.*?)\nPY\b", content, re.DOTALL)
    if not match:
        raise ValueError(f"Could not extract embedded Python from {script_path.name}")
    return match.group(1)

def test_file_format():
    print("[1/5] Checking POSIX line endings and BOM (excluding internal TASK.md)...")
    files = ["install-hy2.sh", "hy2-backup.sh", "README.md", ".gitignore", "test_offline.py"]
    for fname in files:
        fpath = ROOT / fname
        if not fpath.exists():
            continue
        raw = fpath.read_bytes()
        assert not raw.startswith(b'\xef\xbb\xbf'), f"{fname} contains UTF-8 BOM!"
        assert b'\r\n' not in raw, f"{fname} contains CRLF line endings instead of POSIX LF!"
        assert b'\r' not in raw, f"{fname} contains CR line endings!"
    print("PASS: POSIX LF endings and no BOM verified for all distributed files.")

def test_installer_embedded():
    print("[2/5] Testing install-hy2.sh embedded code and configurations...")
    inst_path = ROOT / "install-hy2.sh"
    py_code = extract_embedded_python(inst_path)

    assert "set -euo pipefail" in inst_path.read_text(encoding='utf-8')
    assert "NEEDRESTART_MODE='l'" in py_code

    mod = types.ModuleType("install_hy2_mod")
    # Executing embedded python must be safe (main guarded by if __name__ == '__main__')
    exec(compile(py_code, str(inst_path), "exec"), mod.__dict__)

    assert mod.VERSION == "1.14.4"
    assert mod.SHA256 == "699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968"

    # Default port 443
    mod.validate("node.example.com", "admin@example.com", 443)
    mod.validate("node.example.com", "admin@example.com", 24443)
    for bad_port in [0, -1, -443, 80, 40000, 1023, 65536]:
        try:
            mod.validate("node.example.com", "admin@example.com", bad_port)
            raise AssertionError(f"Accepted invalid port: {bad_port}")
        except ValueError:
            pass

    mod.self_test()
    print("PASS: install-hy2.sh embedded checks, port validation, and routing passed safely.")

def test_backup_embedded():
    print("[3/5] Testing hy2-backup.sh embedded code and security checks...")
    backup_path = ROOT / "hy2-backup.sh"
    py_code = extract_embedded_python(backup_path)

    assert "set -euo pipefail" in backup_path.read_text(encoding='utf-8')

    mod = types.ModuleType("hy2_backup_mod")
    exec(compile(py_code, str(backup_path), "exec"), mod.__dict__)

    mod.self_test()
    print("PASS: hy2-backup.sh self-test passed.")

def test_archive_independent_runner():
    print("[4/5] Executing independent archive verification test logic...")
    backup_path = ROOT / "hy2-backup.sh"
    py_code = extract_embedded_python(backup_path)
    ns = {"__name__": "independent_review"}
    exec(compile(py_code, str(backup_path), "exec"), ns)
    verify = ns["verify_archive"]

    payloads = {
        "/etc/hy2-node/config.json": json.dumps({"inbounds": [{"type": "hysteria2", "listen_port": 443}]}).encode(),
        "/etc/hy2-node/sing-box": b"SYNTHETIC-NOT-EXECUTED",
        "/etc/hy2-node/connection.json": b"{}",
        "/etc/systemd/system/hy2-node.service": b"[Unit]\nDescription=HY2 fixture\n",
        "/var/lib/hy2-subscription/subscription.txt": b"SYNTHETIC",
        "/etc/letsencrypt/archive/node.example.com/fullchain1.pem": b"SYNTHETIC-CERT",
        "/etc/letsencrypt/archive/node.example.com/privkey1.pem": b"SYNTHETIC-KEY",
        "/etc/nginx/sites-available/default": b"server { listen 80; }\n",
    }
    links = {
        "/etc/letsencrypt/live/node.example.com/fullchain.pem": "../../archive/node.example.com/fullchain1.pem",
        "/etc/letsencrypt/live/node.example.com/privkey.pem": "../../archive/node.example.com/privkey1.pem",
        "/etc/nginx/sites-enabled/default": "/etc/nginx/sites-available/default",
    }
    files = [{"path": path, "archive_path": "files" + path, "type": "file", "mode": "0600",
              "uid": 0, "gid": 0, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
             for path, data in payloads.items()]
    files += [{"path": path, "archive_path": "files" + path, "type": "symlink", "mode": "0777",
               "uid": 0, "gid": 0, "link_target": target} for path, target in links.items()]
    manifest = {"manifest_version": "1.0", "created_at": "2026-10-11T00:00:00+00:00",
                "source_machine_id_hash": "0" * 64, "node": {"domain": "node.example.com", "port": 443},
                "files": files, "services": {}}

    def pack(path, cur_payloads, cur_links, cur_manifest, extra=None):
        with tarfile.open(path, "w:gz") as archive:
            for name, data in [("manifest.json", json.dumps(cur_manifest).encode())] + [
                    ("files" + name, data) for name, data in cur_payloads.items()]:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                member.mode = 0o600
                archive.addfile(member, io.BytesIO(data))
            for name, target in cur_links.items():
                member = tarfile.TarInfo("files" + name)
                member.type = tarfile.SYMTYPE
                member.linkname = target
                archive.addfile(member)
            if extra:
                archive.addfile(extra)

    with tempfile.TemporaryDirectory(prefix="offline-test-") as td:
        root = pathlib.Path(td)
        valid = root / "valid.tar.gz"
        pack(valid, payloads, links, manifest)
        verify(valid)

        def reject(label, changed_data=None, changed_links=None, changed_manifest=None, extra=None):
            archive = root / (label + ".tar.gz")
            pack(archive, payloads if changed_data is None else changed_data,
                 links if changed_links is None else changed_links,
                 manifest if changed_manifest is None else changed_manifest, extra)
            try:
                verify(archive)
            except (ValueError, RuntimeError):
                pass
            else:
                raise AssertionError(label + " was accepted")

        # Same-length corruption
        corrupt = dict(payloads)
        original = corrupt["/etc/hy2-node/config.json"]
        corrupt["/etc/hy2-node/config.json"] = b"X" + original[1:]
        reject("hash-mismatch-without-extraction", changed_data=corrupt)

        redirect = copy.deepcopy(manifest)
        redirect["files"][0]["path"] = "/etc/shadow"
        reject("manifest-destination-redirection", changed_manifest=redirect)

        alias = copy.deepcopy(manifest)
        alias["files"][0]["path"] = "/etc/hy2-node/other.json"
        reject("allowed-but-mismatching-destination", changed_manifest=alias)

        duplicate = copy.deepcopy(manifest)
        duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
        reject("duplicate-manifest-entry", changed_manifest=duplicate)

        unsafe_mode = copy.deepcopy(manifest)
        unsafe_mode["files"][1]["mode"] = "04755"
        reject("manifest-suid-mode", changed_manifest=unsafe_mode)

        unsafe_type = copy.deepcopy(manifest)
        unsafe_type["files"][0]["type"] = "unknown"
        reject("unknown-manifest-type", changed_manifest=unsafe_type)

        absent = copy.deepcopy(manifest)
        absent["files"].append({"path": "/etc/hy2-node/missing.json", "archive_path": "files/etc/hy2-node/missing.json",
                                "type": "file", "mode": "0600", "size": 1, "sha256": "0" * 64})
        reject("manifest-member-absent", changed_manifest=absent)

        hardlink = tarfile.TarInfo("files/etc/hy2-node/hardlink")
        hardlink.type = tarfile.LNKTYPE
        hardlink.linkname = "files/etc/hy2-node/config.json"
        reject("hardlink", extra=hardlink)

        escape = dict(links)
        escape["/etc/nginx/sites-enabled/default"] = "/etc/ssh/sshd_config"
        reject("symlink-outside-managed-root", changed_links=escape)

        if os.name == "posix":
            stage = root / "stage"
            verify(valid, extract_to=stage)
            assert (stage / "files/etc/nginx/sites-enabled/default").resolve() == (
                stage / "files/etc/nginx/sites-available/default").resolve()
            assert (stage / "files/etc/letsencrypt/live/node.example.com/fullchain.pem").read_bytes() == b"SYNTHETIC-CERT"

            poisoned = root / "poisoned"
            outside = root / "outside"
            outside.mkdir()
            (poisoned / "files/etc").mkdir(parents=True)
            (poisoned / "files/etc/hy2-node").symlink_to(outside, target_is_directory=True)
            try:
                verify(valid, extract_to=poisoned)
            except (ValueError, RuntimeError):
                pass
            else:
                raise AssertionError("pre-existing staging symlink accepted")
            assert list(outside.iterdir()) == []

            poisoned_leaf = root / "poisoned-leaf"
            (poisoned_leaf / "files/etc/hy2-node").mkdir(parents=True)
            sentinel = outside / "sentinel"
            sentinel.write_bytes(b"UNCHANGED")
            (poisoned_leaf / "files/etc/hy2-node/config.json").symlink_to(sentinel)
            try:
                verify(valid, extract_to=poisoned_leaf)
            except (ValueError, RuntimeError):
                pass
            else:
                raise AssertionError("pre-existing staging leaf symlink accepted")
            assert sentinel.read_bytes() == b"UNCHANGED"

    print("PASS: Archive verification tests passed.")

def test_production_restore_rollback_helper():
    print("[5/5] Testing actual production execute_restore_transaction across inactive-service, stop-failure, rollback-failure...")
    backup_path = ROOT / "hy2-backup.sh"
    py_code = extract_embedded_python(backup_path)
    mod = types.ModuleType("hy2_backup_mod")
    exec(compile(py_code, str(backup_path), "exec"), mod.__dict__)
    execute_restore_transaction = mod.execute_restore_transaction

    import subprocess as sp

    for scenario in ["inactive-service", "stop-failure", "rollback-failure"]:
        with tempfile.TemporaryDirectory(prefix=f"prod-rollback-{scenario}-") as td:
            base = pathlib.Path(td)
            dest = base / "destination"
            stage = base / "stage"
            previous = base / "previous"
            original = {
                "/etc/hy2-node/config.json": b"ORIGINAL_CONFIG",
                "/etc/nginx/sites-available/default": b"ORIGINAL_NGINX",
                "/var/lib/cloudflare-warp/reg.json": b"ORIGINAL_WARP",
            }
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
            live_link.parent.mkdir(parents=True, exist_ok=True)
            live_link.symlink_to("../sites-available/default")
            entries.append({"path": link_name, "archive_path": "files" + link_name,
                            "type": "symlink", "mode": "0777", "link_target": "../sites-available/default"})
            initial = {"hy2-node": True, "warp-svc": True, "nginx": scenario != "inactive-service"}
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
                    raise sp.CalledProcessError(rc, list(args), output=output)
                return sp.CompletedProcess(list(args), rc, stdout=output, stderr="")

            def fail_health():
                events.append(("health",))
                runner("systemctl", "start", "hy2-node")
                runner("systemctl", "start", "nginx")
                raise RuntimeError("INJECTED_HEALTH_FAILURE")

            caught = None
            try:
                execute_restore_transaction(
                    dest_root=dest,
                    manifest={"files": entries},
                    staged_dir=stage,
                    pre_backup_dir=previous,
                    runner=runner,
                    health_check=(lambda: None) if scenario == "stop-failure" else fail_health
                )
            except Exception as error:
                caught = error
            assert caught is not None, scenario + ": expected failure was swallowed"
            for name, expected in original.items():
                assert (dest / name.lstrip("/")).read_bytes() == expected, scenario + ": previous file changed: " + name
            assert not (dest / introduced.lstrip("/")).exists(), scenario + ": introduced file remains"
            assert live_link.is_symlink() and os.readlink(live_link) == "../sites-available/default"
            if scenario == "rollback-failure":
                message = str(caught).lower()
                assert "rollback" in message and ("failed" in message or "incomplete" in message), (
                    "failed daemon recovery was falsely reported as rolled back: " + str(caught))
            else:
                assert services == initial, scenario + ": old daemon state was not restored: " + json.dumps(services)

    print("PASS: Production execute_restore_transaction all 3 scenarios verified.")

def main():
    print("=" * 60)
    print("HY2 Offline Verification Suite")
    print("=" * 60)
    test_file_format()
    test_installer_embedded()
    test_backup_embedded()
    test_archive_independent_runner()
    test_production_restore_rollback_helper()
    print("=" * 60)
    print("ALL OFFLINE TESTS COMPLETED SUCCESSFULLY.")
    print("=" * 60)

if __name__ == '__main__':
    main()

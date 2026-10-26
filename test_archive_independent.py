"""Codex independent archive safety checks; uses synthetic data only."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile


def load_tool(path):
    source = Path(path).read_text(encoding="utf-8")
    code = source.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    ns = {"__name__": "independent_review"}
    exec(compile(code, str(path), "exec"), ns)
    return ns


def fixture():
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
    return payloads, links, manifest


def pack(path, payloads, links, manifest, extra=None):
    with tarfile.open(path, "w:gz") as archive:
        for name, data in [("manifest.json", json.dumps(manifest).encode())] + [
                ("files" + name, data) for name, data in payloads.items()]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o600
            archive.addfile(member, io.BytesIO(data))
        for name, target in links.items():
            member = tarfile.TarInfo("files" + name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)
        if extra:
            archive.addfile(extra)
    path.chmod(0o600)


def main(script):
    ns = load_tool(script)
    verify = ns["verify_archive"]
    with tempfile.TemporaryDirectory(prefix="codex-hy2-archive-tests-") as tmp:
        root = Path(tmp)
        data, links, manifest = fixture()
        valid = root / "valid.tar.gz"
        pack(valid, data, links, manifest)
        verify(valid)
        print("PASS: actual nginx absolute link and LE relative links accepted")

        def reject(label, changed_data=None, changed_links=None, changed_manifest=None, extra=None):
            archive = root / (label + ".tar.gz")
            pack(archive, data if changed_data is None else changed_data,
                 links if changed_links is None else changed_links,
                 manifest if changed_manifest is None else changed_manifest, extra)
            try:
                verify(archive)
            except (ValueError, RuntimeError):
                print("PASS: " + label + " rejected before extraction")
            else:
                raise AssertionError(label + " was accepted")

        corrupt = dict(data)
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
            assert list(outside.iterdir()) == [], "verification wrote through staging symlink"
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
            assert sentinel.read_bytes() == b"UNCHANGED", "verification wrote through leaf symlink"
            print("PASS: extraction stays inside private staging")
    print("ALL CODEX INDEPENDENT ARCHIVE CHECKS PASSED")


if __name__ == "__main__":
    main(sys.argv[1])

#!/usr/bin/env bash
# HY2 private backup, verification and recovery tool.
# Usage:
#   sudo bash hy2-backup.sh backup [--output ARCHIVE_PATH]
#   sudo bash hy2-backup.sh verify ARCHIVE_PATH
#   sudo bash hy2-backup.sh restore ARCHIVE_PATH
#   bash hy2-backup.sh self-test
set -euo pipefail
command -v python3 >/dev/null || { echo 'Please install python3 first: apt-get update && apt-get install -y python3' >&2; exit 1; }
exec python3 - "$@" <<'PY'
import argparse, base64, datetime, hashlib, io, json, os
import pathlib, posixpath, platform, re, shutil, stat, subprocess, sys, tarfile
import tempfile, time, urllib.parse, uuid

try:
    import fcntl
except ImportError:
    fcntl = None

try:
    import sqlite3
except ImportError:
    sqlite3 = None

ALLOWED_PREFIXES = [
    '/etc/hy2-node',
    '/etc/hy2-tcp',
    '/etc/hy2-oneclick',
    '/etc/systemd/system/hy2-node.service',
    '/etc/systemd/system/hy2-node.service.d',
    '/etc/systemd/system/hy2-tcp.service',
    '/etc/systemd/system/hy2-cert-renew.service',
    '/etc/systemd/system/hy2-cert-renew.timer',
    '/var/lib/hy2-subscription',
    '/var/lib/hy2-acme',
    '/etc/letsencrypt',
    '/etc/nginx/sites-available',
    '/etc/nginx/sites-enabled',
    '/etc/nginx/conf.d',
    '/etc/fail2ban/jail.d',
    '/etc/sysctl.d',
    '/var/lib/cloudflare-warp',
]

MAX_ARCHIVE_MEMBERS = 500
MAX_ARCHIVE_SIZE = 256 * 1024 * 1024  # 256 MiB uncompressed limit
LOCK_PATH = pathlib.Path('/run/hy2-node.lock')
TCP_FILES = ['/etc/hy2-tcp/config.json', '/etc/hy2-tcp/connection.json',
             '/etc/systemd/system/hy2-tcp.service']

def archive_has_tcp(manifest):
    entries = manifest.get('files', [])
    if not isinstance(entries, list) or any(not isinstance(e, dict) or not isinstance(e.get('path'), str) for e in entries):
        raise ValueError('Malformed archive file list.')
    paths = {entry['path'] for entry in entries}
    present = paths.intersection(TCP_FILES)
    if present and present != set(TCP_FILES):
        raise ValueError('Incomplete TCP backup: configuration, connection and service are required together.')
    return bool(present)

def validate_connections(config, connection, encoded, tcp_config=None, tcp_connection=None):
    try:
        lines = base64.b64decode(''.join(encoded.split()), validate=True).decode('utf-8').splitlines()
        if not lines or any(not line for line in lines): raise ValueError('empty_subscription')
        hy2 = [line for line in lines if urllib.parse.urlsplit(line).scheme == 'hysteria2']
        vless = [line for line in lines if urllib.parse.urlsplit(line).scheme == 'vless']
        if len(hy2) != 1 or len(lines) != 1 + bool(tcp_config): raise ValueError('unexpected_node_count')
        inbound = next(ib for ib in config['inbounds'] if ib['type'] == 'hysteria2')
        parsed = urllib.parse.urlsplit(hy2[0])
        if urllib.parse.unquote(parsed.username or '') != inbound['users'][0]['password'] or parsed.port != inbound['listen_port']:
            raise ValueError('hy2_credentials_differ')
        if connection and connection.get('uri') != hy2[0]: raise ValueError('hy2_uri_differ')
        if tcp_config is not None:
            if len(vless) != 1 or not tcp_connection or tcp_connection.get('uri') != vless[0]:
                raise ValueError('tcp_uri_differ')
            ibs = tcp_config['inbounds']
            if len(ibs) != 1: raise ValueError('unexpected_tcp_inbounds')
            ib = ibs[0]
            if (ib.get('type'), ib.get('listen'), ib.get('listen_port')) != ('vless', '127.0.0.1', 18080):
                raise ValueError('unsafe_tcp_listener')
            if ib.get('tls', {}).get('enabled'): raise ValueError('backend_tls_must_terminate_at_nginx')
            if ib['transport'].get('type') != 'ws': raise ValueError('unexpected_tcp_transport')
            tcp = urllib.parse.urlsplit(vless[0]); q = urllib.parse.parse_qs(tcp.query)
            uuid.UUID(ib['users'][0]['uuid'])
            if tcp.username != ib['users'][0]['uuid'] or tcp.port != 443: raise ValueError('tcp_credentials_differ')
            if tcp.hostname != parsed.hostname: raise ValueError('node_addresses_differ')
            if q.get('path') != [ib['transport']['path']] or q.get('type') != ['ws'] or q.get('security') != ['tls']:
                raise ValueError('tcp_transport_differ')
            sni = urllib.parse.parse_qs(parsed.query).get('sni', [parsed.hostname])
            if q.get('sni') != sni or q.get('host') != sni or q.get('alpn') != ['http/1.1']:
                raise ValueError('tcp_tls_host_differ')
            if q.get('allowInsecure', ['0']) not in (['0'], ['false']): raise ValueError('insecure_tcp_uri')
            for key in ('dns', 'route', 'outbounds'):
                if config[key] != tcp_config[key]: raise ValueError('node_routing_differ')
    except Exception:
        raise ValueError('Node/subscription consistency validation failed; inspect private files locally.') from None

def run(*args, capture=False, check=True):
    return subprocess.run(args, text=True, check=check,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(65536)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()

def get_machine_id_hash() -> str:
    for p in [pathlib.Path('/etc/machine-id'), pathlib.Path('/var/lib/dbus/machine-id')]:
        if p.exists():
            try:
                mid = p.read_text().strip()
                if mid:
                    return hashlib.sha256(mid.encode('utf-8')).hexdigest()
            except Exception:
                pass
    return 'unknown'

def is_canonical_path(p: str) -> bool:
    if not p.startswith('/') or '//' in p or p.endswith('/'):
        return False
    parts = p.split('/')
    if any(part in ('', '.', '..') for part in parts[1:]):
        return False
    return True

def is_path_allowed(target_path: str) -> bool:
    if not is_canonical_path(target_path):
        return False
    norm = posixpath.normpath(target_path)
    for prefix in ALLOWED_PREFIXES:
        if norm == prefix or norm.startswith(prefix + '/'):
            return True
    return False

def acquire_shared_lock():
    if fcntl:
        try:
            LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
            lock_fd = open(LOCK_PATH, 'w')
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock_fd
        except OSError:
            raise RuntimeError('Another HY2 install or backup/restore operation is currently running.')
    return None

def discover_backup_items(temp_files_to_clean):
    items = []
    base_dir = pathlib.Path('/etc/hy2-node')
    config_file = base_dir / 'config.json'
    sing_box_file = base_dir / 'sing-box'
    service_file = pathlib.Path('/etc/systemd/system/hy2-node.service')

    if not config_file.exists():
        raise RuntimeError('Missing mandatory HY2 config: /etc/hy2-node/config.json')
    if not sing_box_file.exists():
        raise RuntimeError('Missing mandatory HY2 binary: /etc/hy2-node/sing-box')
    if not service_file.exists():
        raise RuntimeError('Missing mandatory HY2 systemd service: /etc/systemd/system/hy2-node.service')

    items.append((config_file, '/etc/hy2-node/config.json', 'file'))
    items.append((sing_box_file, '/etc/hy2-node/sing-box', 'file'))
    items.append((service_file, '/etc/systemd/system/hy2-node.service', 'file'))

    conn_file = base_dir / 'connection.json'
    if conn_file.exists():
        items.append((conn_file, '/etc/hy2-node/connection.json', 'file'))

    dropin_dir = pathlib.Path('/etc/systemd/system/hy2-node.service.d')
    if dropin_dir.is_dir():
        for f in sorted(dropin_dir.glob('*.conf')):
            if f.is_file():
                items.append((f, '/etc/systemd/system/hy2-node.service.d/' + f.name, 'file'))

    oneclick_dir = pathlib.Path('/etc/hy2-oneclick')
    if oneclick_dir.is_dir():
        for f in sorted(oneclick_dir.iterdir()):
            if f.is_file():
                items.append((f, '/etc/hy2-oneclick/' + f.name, 'file'))

    sub_dir = pathlib.Path('/var/lib/hy2-subscription')
    sub_file = None
    if sub_dir.is_dir():
        for sname in ['subscription.txt', 'sub.txt']:
            sf = sub_dir / sname
            if sf.exists() and sf.is_file():
                sub_file = sf
                items.append((sf, '/var/lib/hy2-subscription/' + sname, 'file'))
                break
        if not sub_file:
            for sf in sorted(sub_dir.glob('*.txt')):
                if sf.is_file():
                    sub_file = sf
                    items.append((sf, '/var/lib/hy2-subscription/' + sf.name, 'file'))
                    break
    if not sub_file:
        raise RuntimeError('Missing mandatory subscription file in /var/lib/hy2-subscription/')

    hash_cfg_pre = sha256_file(config_file)
    hash_sub_pre = sha256_file(sub_file)
    hash_conn_pre = sha256_file(conn_file) if conn_file.exists() else None

    try:
        conf_data = json.loads(config_file.read_text(encoding='utf-8'))
    except Exception as e:
        raise RuntimeError('Failed to parse /etc/hy2-node/config.json: ' + str(e))

    node_port = None
    node_pass = None
    cert_path_str = None
    for ib in conf_data.get('inbounds', []):
        if ib.get('type') == 'hysteria2':
            node_port = ib.get('listen_port')
            users = ib.get('users', [])
            if users: node_pass = users[0].get('password')
            tls = ib.get('tls', {})
            cert_path_str = tls.get('certificate_path')
            break

    if not cert_path_str or node_port is None or not node_pass:
        raise RuntimeError('Invalid /etc/hy2-node/config.json: missing port, password, or certificate path.')

    tcp_paths = [pathlib.Path(p) for p in TCP_FILES]
    tcp_present = any(p.exists() for p in tcp_paths)
    tcp_data = tcp_conn = None
    extra_digests = {}
    if tcp_present:
        for path in tcp_paths:
            if not path.is_file() or path.is_symlink(): raise RuntimeError('Incomplete or unsafe TCP backup files.')
            items.append((path, str(path), 'file'))
            extra_digests[str(path)] = sha256_file(path)
        tcp_data = json.loads(tcp_paths[0].read_text())
        tcp_conn = json.loads(tcp_paths[1].read_text())
    validate_connections(conf_data, json.loads(conn_file.read_text()) if conn_file.exists() else None,
                         sub_file.read_text(), tcp_data, tcp_conn)

    if conn_file.exists():
        try:
            conn_data = json.loads(conn_file.read_text(encoding='utf-8'))
            conn_uri = conn_data.get('uri', '')
            parsed_conn = urllib.parse.urlsplit(conn_uri)
            conn_pw = urllib.parse.unquote(parsed_conn.username or '')
            if not conn_pw and '@' in parsed_conn.netloc:
                conn_pw = urllib.parse.unquote(parsed_conn.netloc.split('@')[0].split(':')[0])
            if conn_pw != node_pass or parsed_conn.port != node_port:
                raise RuntimeError('connection.json URI credentials do not match active config.json!')
        except Exception as e:
            raise RuntimeError('connection.json consistency validation failed: ' + str(e))

    cert_domain = None
    m = re.search(r'/etc/letsencrypt/live/([^/]+)/', cert_path_str)
    if m:
        cert_domain = m.group(1)
        le_live = pathlib.Path('/etc/letsencrypt/live') / cert_domain
        le_archive = pathlib.Path('/etc/letsencrypt/archive') / cert_domain
        le_renewal = pathlib.Path('/etc/letsencrypt/renewal') / (cert_domain + '.conf')

        if le_archive.is_dir():
            for af in sorted(le_archive.iterdir()):
                if af.is_file():
                    items.append((af, '/etc/letsencrypt/archive/' + cert_domain + '/' + af.name, 'file'))

        if le_live.is_dir():
            for lf in sorted(le_live.iterdir()):
                target_dest = '/etc/letsencrypt/live/' + cert_domain + '/' + lf.name
                if lf.is_symlink():
                    link_tgt = os.readlink(lf)
                    items.append((lf, target_dest, 'symlink', link_tgt))
                elif lf.is_file():
                    items.append((lf, target_dest, 'file'))

        if le_renewal.is_file():
            items.append((le_renewal, '/etc/letsencrypt/renewal/' + cert_domain + '.conf', 'file'))

    le_accounts = pathlib.Path('/etc/letsencrypt/accounts')
    if le_accounts.is_dir():
        for root, dirs, files in os.walk(le_accounts):
            for file_name in sorted(files):
                full_p = pathlib.Path(root) / file_name
                items.append((full_p, str(full_p).replace('\\', '/'), 'file'))

    le_hooks = pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy')
    if le_hooks.is_dir():
        for hf in sorted(le_hooks.iterdir()):
            if hf.is_file():
                try:
                    txt = hf.read_text(encoding='utf-8', errors='ignore')
                    if 'hy2' in txt or 'nginx' in txt:
                        items.append((hf, str(hf).replace('\\', '/'), 'file'))
                except Exception:
                    pass

    for unit_p in ['/etc/systemd/system/hy2-cert-renew.service', '/etc/systemd/system/hy2-cert-renew.timer']:
        up = pathlib.Path(unit_p)
        if up.exists() and up.is_file():
            items.append((up, unit_p, 'file'))

    acme_dir = pathlib.Path('/var/lib/hy2-acme')
    if acme_dir.is_dir():
        items.append((acme_dir, '/var/lib/hy2-acme', 'dir'))

    nginx_candidates = []
    for cand_dir in ['/etc/nginx/sites-available', '/etc/nginx/conf.d']:
        cd = pathlib.Path(cand_dir)
        if cd.is_dir():
            for cf in sorted(cd.iterdir()):
                if cf.is_file():
                    try:
                        content = cf.read_text(encoding='utf-8', errors='ignore')
                        if 'hy2-subscription' in content or (cert_path_str and cert_path_str in content) or (cert_domain and cert_domain in content):
                            nginx_candidates.append(cf)
                            items.append((cf, str(cf).replace('\\', '/'), 'file'))
                    except Exception:
                        pass

    sites_enabled = pathlib.Path('/etc/nginx/sites-enabled')
    if sites_enabled.is_dir():
        cand_names = {c.name for c in nginx_candidates}
        for ef in sorted(sites_enabled.iterdir()):
            if ef.is_symlink():
                link_target = os.readlink(ef)
                tgt_name = pathlib.Path(link_target).name
                if tgt_name in cand_names or ef.name in cand_names:
                    items.append((ef, '/etc/nginx/sites-enabled/' + ef.name, 'symlink', link_target))
            elif ef.is_file():
                try:
                    content = ef.read_text(encoding='utf-8', errors='ignore')
                    if 'hy2-subscription' in content or (cert_path_str and cert_path_str in content):
                        items.append((ef, '/etc/nginx/sites-enabled/' + ef.name, 'file'))
                except Exception:
                    pass

    f2b_dir = pathlib.Path('/etc/fail2ban/jail.d')
    if f2b_dir.is_dir():
        for jf in sorted(f2b_dir.glob('*hy2*.local')):
            if jf.is_file():
                items.append((jf, '/etc/fail2ban/jail.d/' + jf.name, 'file'))

    sysctl_dir = pathlib.Path('/etc/sysctl.d')
    if sysctl_dir.is_dir():
        for sf in sorted(sysctl_dir.glob('*hy2*.conf')):
            if sf.is_file():
                items.append((sf, '/etc/sysctl.d/' + sf.name, 'file'))

    warp_dir = pathlib.Path('/var/lib/cloudflare-warp')
    if warp_dir.is_dir():
        for wf in sorted(warp_dir.iterdir()):
            if wf.is_file():
                if wf.name.endswith(('.log', '.tmp', '.lock', '.sock')):
                    continue
                if wf.suffix in ['.db', '.sqlite']:
                    if sqlite3 is not None:
                        try:
                            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tf:
                                tmp_db = pathlib.Path(tf.name)
                            temp_files_to_clean.append(tmp_db)
                            src_conn = sqlite3.connect(f'file:{wf}?mode=ro', uri=True)
                            dst_conn = sqlite3.connect(str(tmp_db))
                            try:
                                with dst_conn:
                                    src_conn.backup(dst_conn)
                            finally:
                                dst_conn.close()
                                src_conn.close()
                            items.append((tmp_db, '/var/lib/cloudflare-warp/' + wf.name, 'file'))
                            continue
                        except Exception as sqle:
                            sys.stderr.write(f'Notice: Omitting SQLite database {wf.name} (live backup failed: {sqle})\n')
                            continue
                    else:
                        sys.stderr.write(f'Notice: Omitting SQLite database {wf.name} (sqlite3 module unavailable)\n')
                        continue
                items.append((wf, '/var/lib/cloudflare-warp/' + wf.name, 'file'))

    digests_pre = {
        'config': hash_cfg_pre,
        'sub': hash_sub_pre,
        'conn': hash_conn_pre,
        'extra': extra_digests,
    }
    return items, conf_data, cert_domain, node_port, digests_pre, sub_file

def create_backup(output_path=None):
    if os.name == 'posix' and os.geteuid() != 0:
        raise RuntimeError('Backup requires root privileges to read managed node keys and configuration.')

    lock_fd = acquire_shared_lock()
    old_umask = os.umask(0o077)
    temp_files_to_clean = []

    try:
        items, conf_data, cert_domain, node_port, digests_pre, sub_file = discover_backup_items(temp_files_to_clean)

        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        if not output_path:
            out_dir = pathlib.Path('/var/backups/hy2-oneclick')
            out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            output_path = out_dir / ('hy2-backup-' + stamp + '.tar.gz')
        else:
            output_path = pathlib.Path(output_path)
            if is_path_allowed(str(output_path).replace('\\', '/')):
                raise ValueError('Backup output path cannot be inside managed node paths: ' + str(output_path))
            if output_path.exists() or output_path.is_symlink():
                raise ValueError('Backup output archive already exists or is a symlink: ' + str(output_path))
            output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        temp_tar = output_path.with_name(output_path.name + '.tmp')
        if temp_tar.exists() or temp_tar.is_symlink():
            raise ValueError('Temporary archive output path already exists or is a symlink: ' + str(temp_tar))

        with tempfile.TemporaryDirectory(prefix='hy2-backup-stage-') as td:
            tdp = pathlib.Path(td)
            tdp.chmod(0o700)
            files_dir = tdp / 'files'
            files_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

            manifest_files = []
            for item in items:
                src_path = item[0]
                dest_norm = posixpath.normpath(item[1])
                rel_in_archive = 'files' + dest_norm
                staged_path = tdp / rel_in_archive

                if item[2] == 'dir':
                    staged_path.mkdir(parents=True, exist_ok=True, mode=0o755)
                    manifest_files.append({
                        'path': dest_norm,
                        'archive_path': rel_in_archive,
                        'type': 'dir',
                        'mode': '0755',
                    })
                elif item[2] == 'symlink':
                    staged_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    link_tgt = item[3]
                    if staged_path.is_symlink() or staged_path.exists():
                        staged_path.unlink()
                    os.symlink(link_tgt, staged_path)
                    manifest_files.append({
                        'path': dest_norm,
                        'archive_path': rel_in_archive,
                        'type': 'symlink',
                        'link_target': link_tgt,
                        'mode': '0777',
                    })
                else:
                    staged_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    shutil.copy2(src_path, staged_path)
                    staged_bytes = staged_path.read_bytes()
                    f_mode = oct(src_path.stat().st_mode & 0o777)
                    st = src_path.stat()
                    manifest_files.append({
                        'path': dest_norm,
                        'archive_path': rel_in_archive,
                        'type': 'file',
                        'mode': f_mode,
                        'uid': st.st_uid,
                        'gid': st.st_gid,
                        'size': len(staged_bytes),
                        'sha256': sha256_bytes(staged_bytes),
                    })

            base_dir = pathlib.Path('/etc/hy2-node')
            staged_cfg = tdp / 'files/etc/hy2-node/config.json'
            if sha256_file(base_dir / 'config.json') != digests_pre['config'] or sha256_file(staged_cfg) != digests_pre['config']:
                raise RuntimeError('Production config modified during capture; aborting.')

            sub_dest = None
            for mf in manifest_files:
                if mf['path'].startswith('/var/lib/hy2-subscription/'):
                    sub_dest = tdp / mf['archive_path']
                    break
            if sha256_file(sub_file) != digests_pre['sub'] or (sub_dest and sha256_file(sub_dest) != digests_pre['sub']):
                raise RuntimeError('Subscription file modified during capture; aborting.')

            conn_file = base_dir / 'connection.json'
            staged_conn = tdp / 'files/etc/hy2-node/connection.json'
            if conn_file.exists() and digests_pre['conn']:
                if sha256_file(conn_file) != digests_pre['conn'] or sha256_file(staged_conn) != digests_pre['conn']:
                    raise RuntimeError('connection.json modified during capture; aborting.')

            manifest = {
                'manifest_version': '1.0',
                'created_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'source_machine_id_hash': get_machine_id_hash(),
                'node': {
                    'domain': cert_domain or 'unknown',
                    'port': node_port or 443,
                },
                'files': manifest_files,
                'services': {
                    'hy2-node': {'unit': '/etc/systemd/system/hy2-node.service'}
                }
            }
            for name, expected in digests_pre.get('extra', {}).items():
                if sha256_file(pathlib.Path(name)) != expected or sha256_file(tdp / ('files' + name)) != expected:
                    raise RuntimeError('TCP file modified during capture; aborting.')
            if archive_has_tcp(manifest):
                manifest['services']['hy2-tcp'] = {'unit': '/etc/systemd/system/hy2-tcp.service'}

            manifest_path = tdp / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
            manifest_path.chmod(0o600)

            with tarfile.open(temp_tar, mode='w:gz') as tar:
                tar.add(manifest_path, arcname='manifest.json')
                for mf in manifest['files']:
                    arc_name = mf['archive_path']
                    local_path = tdp / arc_name
                    tar.add(local_path, arcname=arc_name, recursive=False)

            temp_tar.chmod(0o600)
            os.replace(temp_tar, output_path)

            verify_archive(output_path)

        print('Backup completed and verified successfully.')
        print('Archive location:', output_path)
        print('Archive size:', output_path.stat().st_size, 'bytes')
        print('Archive SHA256:', sha256_file(output_path))
        print('Manifest items count:', len(manifest['files']))
        print('Domain/Host:', manifest['node']['domain'])
        print('Port:', manifest['node']['port'])
    finally:
        for tmp_f in temp_files_to_clean:
            try: tmp_f.unlink(missing_ok=True)
            except Exception: pass
        os.umask(old_umask)
        if lock_fd:
            try: lock_fd.close()
            except Exception: pass

def verify_archive(archive_path, extract_to=None):
    arch = pathlib.Path(archive_path)
    if not arch.exists() or not arch.is_file():
        raise RuntimeError('Archive file not found: ' + str(archive_path))

    if os.name == 'posix':
        mode = arch.stat().st_mode & 0o777
        if mode != 0o600:
            sys.stderr.write('Warning: Archive permissions should be 0600 (currently ' + oct(mode) + ').\n')

    with tarfile.open(arch, mode='r:gz') as tar:
        members = tar.getmembers()
        if len(members) > MAX_ARCHIVE_MEMBERS:
            raise ValueError('Archive member count exceeds limit: ' + str(len(members)))
        total_uncompressed = sum(m.size for m in members)
        if total_uncompressed > MAX_ARCHIVE_SIZE:
            raise ValueError('Archive uncompressed size exceeds limit.')

        member_names = [m.name for m in members]
        if len(member_names) != len(set(member_names)):
            raise ValueError('Duplicate member in archive')

        member_map = {m.name: m for m in members}

        manifest_member = member_map.get('manifest.json')
        if not manifest_member or not manifest_member.isfile():
            raise ValueError('Missing or invalid manifest.json in archive.')

        f = tar.extractfile(manifest_member)
        if not f:
            raise ValueError('Unable to read manifest.json from archive.')
        try:
            manifest = json.loads(f.read().decode('utf-8'))
        except Exception as e:
            raise ValueError('Invalid JSON in manifest.json: ' + str(e))

        if manifest.get('manifest_version') != '1.0':
            raise ValueError('Unrecognized manifest_version: ' + str(manifest.get('manifest_version')))

        m_files_list = manifest.get('files', [])
        if not isinstance(m_files_list, list):
            raise ValueError('manifest files must be a list')
        archive_has_tcp(manifest)

        seen_paths = set()
        seen_arc_paths = set()
        manifest_files = {}
        for entry in m_files_list:
            p = entry.get('path')
            ap = entry.get('archive_path')
            if not p or not ap:
                raise ValueError('Manifest entry missing path or archive_path')
            if p in seen_paths or ap in seen_arc_paths:
                raise ValueError('Duplicate manifest entry: ' + str(p))
            seen_paths.add(p)
            seen_arc_paths.add(ap)
            manifest_files[ap] = entry

        non_manifest_members = [m for m in members if m.name != 'manifest.json']
        if len(non_manifest_members) != len(manifest_files):
            raise ValueError('Archive members count does not match manifest files count')

        symlink_members = set()

        for m in members:
            if m.islnk():
                raise ValueError('Hardlinks are forbidden in archive: ' + m.name)

            if not (m.isfile() or m.issym() or m.isdir()):
                raise ValueError('Unsafe or special member type (device/FIFO): ' + m.name)

            if m.name == 'manifest.json':
                continue

            if not m.name.startswith('files/'):
                raise ValueError('Unexpected member outside files/: ' + m.name)

            dst_path = '/' + m.name[len('files/'):]
            if not is_path_allowed(dst_path):
                raise ValueError('Unexpected or non-canonical destination path in archive: ' + dst_path)

            if m.name not in manifest_files:
                raise ValueError('Archive member not present in manifest: ' + m.name)

            mf = manifest_files[m.name]
            if mf.get('path') != dst_path:
                raise ValueError('Manifest path mismatch for member: ' + m.name)
            if mf.get('archive_path') != m.name:
                raise ValueError('Manifest archive_path mismatch for member: ' + m.name)

            mf_type = mf.get('type')
            if mf_type not in ('file', 'dir', 'symlink'):
                raise ValueError('Unknown or unsafe manifest type: ' + str(mf_type))

            raw_mode = mf.get('mode')
            try:
                int_mode = int(str(raw_mode), 8) if isinstance(raw_mode, str) else int(raw_mode)
            except (ValueError, TypeError):
                raise ValueError('Invalid manifest mode: ' + str(raw_mode))
            if int_mode < 0 or (int_mode & ~0o777) != 0:
                raise ValueError('Manifest mode out of range 0..0777 or contains suid/sgid/sticky: ' + oct(int_mode))

            if m.mode < 0 or (m.mode & ~0o777) != 0:
                raise ValueError('Tar member mode out of range 0..0777 or contains suid/sgid/sticky: ' + oct(m.mode))

            if mf_type == 'file' and not m.isfile():
                raise ValueError('Type mismatch in manifest for file: ' + m.name)
            if mf_type == 'symlink' and not m.issym():
                raise ValueError('Type mismatch in manifest for symlink: ' + m.name)
            if mf_type == 'dir' and not m.isdir():
                raise ValueError('Type mismatch in manifest for dir: ' + m.name)

            if m.issym():
                symlink_members.add(m.name)
                link_target = m.linkname
                if mf.get('link_target') != link_target:
                    raise ValueError('Manifest symlink target mismatch for member: ' + m.name)

                if link_target.startswith('/'):
                    dest_member_name = 'files' + link_target
                    if not is_path_allowed(link_target):
                        raise ValueError('Absolute symlink target outside allowed managed root: ' + link_target)
                else:
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(m.name), link_target))
                    if not resolved.startswith('files/'):
                        raise ValueError('Symlink target escapes snapshot files/ root: ' + link_target)
                    resolved_dst = '/' + resolved[len('files/'):]
                    if not is_path_allowed(resolved_dst):
                        raise ValueError('Symlink target escapes allowed managed root: ' + resolved_dst)
                    dest_member_name = resolved

                target_m = member_map.get(dest_member_name)
                if not target_m or not target_m.isfile():
                    raise ValueError('Symlink target must be an existing regular file member in snapshot: ' + link_target)

            if m.isfile():
                if m.size != mf.get('size'):
                    raise ValueError('Size mismatch for ' + m.name + ': expected ' + str(mf.get('size')) + ' got ' + str(m.size))
                content = tar.extractfile(m).read()
                actual_hash = sha256_bytes(content)
                if actual_hash != mf.get('sha256'):
                    raise ValueError('Hash mismatch for ' + m.name + ': expected ' + str(mf.get('sha256')) + ' got ' + actual_hash)

        for m in members:
            for sname in symlink_members:
                if m.name != sname and m.name.startswith(sname + '/'):
                    raise ValueError('Unsafe symlink parent directory in archive: ' + sname)

        required_managed = ['/etc/hy2-node/config.json', '/etc/hy2-node/sing-box', '/etc/systemd/system/hy2-node.service']
        for req in required_managed:
            req_arc_name = 'files' + req
            req_member = member_map.get(req_arc_name)
            if not req_member or not req_member.isfile():
                raise ValueError('Missing mandatory regular node file in archive: ' + req)

        sub_found = any(p.startswith('/var/lib/hy2-subscription/') and member_map['files' + p].isfile()
                        for p in seen_paths)
        if not sub_found:
            raise ValueError('Missing mandatory regular subscription file in archive.')

        if extract_to:
            staging_path = pathlib.Path(extract_to)
            if staging_path.is_symlink():
                raise ValueError('Staging root is a symlink: ' + str(staging_path))
            staging_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            if os.name == 'posix':
                staging_path.chmod(0o700)

            for m in members:
                target = staging_path / m.name
                if target.is_symlink():
                    raise ValueError('Pre-existing staging leaf is a symlink: ' + str(target))
                cur = target.parent
                while True:
                    if cur.is_symlink():
                        raise ValueError('Pre-existing staging ancestor is a symlink: ' + str(cur))
                    if cur == staging_path or cur in staging_path.parents or cur == cur.parent:
                        break
                    cur = cur.parent

            for m in members:
                if m.isdir():
                    target = staging_path / m.name
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)

            for m in members:
                if m.isfile() and m.name != 'manifest.json':
                    target = staging_path / m.name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    mf = manifest_files[m.name]
                    content = tar.extractfile(m).read()
                    target.write_bytes(content)
                    try:
                        target.chmod(int(str(mf.get('mode', '0600')), 8))
                    except Exception:
                        pass
                    if 'uid' in mf and 'gid' in mf and os.name == 'posix':
                        try: shutil.chown(target, user=mf['uid'], group=mf['gid'])
                        except Exception: pass

            for m in members:
                if m.issym():
                    target = staging_path / m.name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    if target.is_symlink() or target.exists():
                        target.unlink()
                    link_target = m.linkname
                    if link_target.startswith('/'):
                        staged_target_rel = posixpath.relpath('files' + link_target, posixpath.dirname(m.name))
                        os.symlink(staged_target_rel, target)
                    else:
                        os.symlink(link_target, target)

            (staging_path / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    print('Archive verified successfully.')
    print('Manifest version:', manifest.get('manifest_version'))
    print('Created at:', manifest.get('created_at'))
    print('Files checked:', len(manifest_files))
    print('Source machine ID hash:', manifest.get('source_machine_id_hash'))
    print('Domain/Host:', manifest.get('node', {}).get('domain'))
    print('Port:', manifest.get('node', {}).get('port'))
    return manifest

def execute_restore_transaction(dest_root: pathlib.Path, manifest: dict, staged_dir: pathlib.Path,
                                pre_backup_dir: pathlib.Path, runner=run, health_check=None):
    dest_root = pathlib.Path(dest_root).resolve()
    tcp_archived = archive_has_tcp(manifest)
    if not tcp_archived and any((dest_root / name.lstrip('/')).exists() for name in TCP_FILES):
        raise ValueError('Archive lacks the existing TCP node; use a recent complete backup.')
    pre_backup_dir = pathlib.Path(pre_backup_dir).resolve()
    pre_backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # 1. Check destination ancestor symlinks before any mutations
    for mf in manifest['files']:
        rel_clean = mf['path'].lstrip('/')
        dest_p = dest_root / rel_clean
        cur = dest_p.parent
        while True:
            if cur.is_symlink():
                raise ValueError('Destination ancestor is a symlink: ' + str(cur))
            if cur == dest_root or cur in dest_root.parents or cur == cur.parent:
                break
            cur = cur.parent

    # 2. Snapshot current state preserving full relative paths and metadata
    rollback_metadata = []
    initial_services = {}
    service_names = ['hy2-node', 'warp-svc', 'nginx'] + (['hy2-tcp'] if tcp_archived else [])
    tcp_initial_enabled = (runner('systemctl','is-enabled','hy2-tcp',capture=True,check=False).returncode == 0) if tcp_archived else False
    for svc in service_names:
        try:
            res = runner('systemctl', 'is-active', svc, capture=True, check=False)
            initial_services[svc] = (res.returncode == 0)
        except Exception:
            initial_services[svc] = False

    for mf in manifest['files']:
        rel_clean = mf['path'].lstrip('/')
        dest_p = dest_root / rel_clean
        backup_p = pre_backup_dir / ('files/' + rel_clean)
        if dest_p.is_symlink():
            backup_p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            link_tgt = os.readlink(dest_p)
            os.symlink(link_tgt, backup_p)
            rollback_metadata.append({'path': rel_clean, 'existed': True, 'type': 'symlink', 'link_target': link_tgt})
        elif dest_p.is_file():
            backup_p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            shutil.copy2(dest_p, backup_p)
            st = dest_p.stat()
            rollback_metadata.append({'path': rel_clean, 'existed': True, 'type': 'file', 'mode': st.st_mode, 'uid': st.st_uid, 'gid': st.st_gid})
        elif dest_p.is_dir():
            backup_p.mkdir(parents=True, exist_ok=True, mode=0o755)
            rollback_metadata.append({'path': rel_clean, 'existed': True, 'type': 'dir'})
        else:
            rollback_metadata.append({'path': rel_clean, 'existed': False, 'type': mf['type']})

    has_warp_files = any(mf['path'].startswith('/var/lib/cloudflare-warp/') for mf in manifest['files'])
    file_deployment_started = False
    rollback_errors = []

    try:
        # Checked service stops INSIDE protected try, before any live file mutation
        if initial_services.get('hy2-node', False):
            runner('systemctl', 'stop', 'hy2-node', check=True)
        if initial_services.get('hy2-tcp', False):
            runner('systemctl', 'stop', 'hy2-tcp', check=True)
        if has_warp_files and initial_services.get('warp-svc', False):
            runner('systemctl', 'stop', 'warp-svc', check=True)

        # Immediately AFTER successfully stopping warp-svc and BEFORE file mutation,
        # refresh WARP entries' pre_backup copies from stopped live files to ensure a clean SQLite snapshot.
        if has_warp_files:
            for rb in rollback_metadata:
                if rb['path'].startswith('var/lib/cloudflare-warp/') and rb['existed'] and rb['type'] == 'file':
                    dest_p = dest_root / rb['path']
                    backup_p = pre_backup_dir / ('files/' + rb['path'])
                    if dest_p.is_file():
                        backup_p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        shutil.copy2(dest_p, backup_p)
                        st = dest_p.stat()
                        rb['mode'] = st.st_mode
                        rb['uid'] = st.st_uid
                        rb['gid'] = st.st_gid

        file_deployment_started = True

        for mf in manifest['files']:
            rel_clean = mf['path'].lstrip('/')
            dest_p = dest_root / rel_clean
            staged_p = staged_dir / mf['archive_path']
            dest_p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            if mf['type'] == 'dir':
                dest_p.mkdir(parents=True, exist_ok=True, mode=0o755)
            elif mf['type'] == 'symlink':
                dest_p.unlink(missing_ok=True)
                os.symlink(mf['link_target'], dest_p)
            else:
                temp_sibling = dest_p.with_name(dest_p.name + '.restoring')
                shutil.copy2(staged_p, temp_sibling)
                try:
                    temp_sibling.chmod(int(str(mf.get('mode', '0600')), 8))
                except Exception:
                    pass
                if 'uid' in mf and 'gid' in mf and os.name == 'posix':
                    try: shutil.chown(temp_sibling, user=mf['uid'], group=mf['gid'])
                    except Exception: pass
                os.replace(temp_sibling, dest_p)

        sub_dir = dest_root / 'var/lib/hy2-subscription'
        if sub_dir.is_dir() and os.name == 'posix':
            try:
                shutil.chown(sub_dir, user='root', group='www-data')
                sub_dir.chmod(0o750)
                for sf in sub_dir.glob('*.txt'):
                    shutil.chown(sf, user='root', group='www-data')
                    sf.chmod(0o640)
            except Exception:
                pass

        if has_warp_files and initial_services.get('warp-svc', False):
            runner('systemctl', 'start', 'warp-svc', check=True)

        if health_check:
            health_check()
    except Exception as exc:
        sys.stderr.write('Deployment or health verification failed; rolling back...\n')
        if file_deployment_started:
            if tcp_archived:
                try: runner('systemctl', 'stop', 'hy2-tcp', check=True)
                except Exception as e: rollback_errors.append(f'Failed to stop TCP during rollback: {e}')
            try:
                runner('systemctl', 'stop', 'hy2-node', check=True)
            except Exception as e:
                rollback_errors.append(f'Failed to stop hy2-node during rollback: {e}')

            warp_stop_ok = True
            if has_warp_files:
                try:
                    runner('systemctl', 'stop', 'warp-svc', check=True)
                except Exception as e:
                    warp_stop_ok = False
                    rollback_errors.append(f'Failed to stop warp-svc during rollback: {e}')

            for rb in rollback_metadata:
                dest_p = dest_root / rb['path']
                bk_p = pre_backup_dir / ('files/' + rb['path'])

                if rb['path'].startswith('var/lib/cloudflare-warp/') and not warp_stop_ok:
                    rollback_errors.append(f'Skipped restoring live WARP state file {rb["path"]} because warp-svc could not be stopped')
                    continue

                try:
                    if rb['existed']:
                        if rb['type'] == 'symlink':
                            dest_p.unlink(missing_ok=True)
                            os.symlink(rb['link_target'], dest_p)
                        elif rb['type'] == 'file':
                            temp_rb = dest_p.with_name(dest_p.name + '.rb')
                            shutil.copy2(bk_p, temp_rb)
                            if 'mode' in rb:
                                try: temp_rb.chmod(rb['mode'])
                                except Exception: pass
                            if 'uid' in rb and 'gid' in rb and os.name == 'posix':
                                try: shutil.chown(temp_rb, user=rb['uid'], group=rb['gid'])
                                except Exception: pass
                            os.replace(temp_rb, dest_p)
                    else:
                        if rb['type'] == 'dir':
                            try: dest_p.rmdir()
                            except OSError: pass
                        else:
                            dest_p.unlink(missing_ok=True)
                except Exception as fe:
                    rollback_errors.append(f'Failed restoring {rb["path"]}: {fe}')

        # Call checked systemctl daemon-reload after restoring files and before recovering services
        try:
            runner('systemctl', 'daemon-reload', check=True)
        except Exception as de:
            rollback_errors.append(f'Failed daemon-reload during rollback: {de}')

        # Service recovery: restart originally active services (with nginx -t check), keep originally inactive stopped
        if tcp_archived:
            try: runner('systemctl', 'enable' if tcp_initial_enabled else 'disable', 'hy2-tcp', check=False)
            except Exception as e: rollback_errors.append(f'Failed TCP enable-state rollback: {e}')
        for svc in ['warp-svc', 'hy2-node', 'nginx'] + (['hy2-tcp'] if tcp_archived else []):
            was_active = initial_services.get(svc, False)
            try:
                if was_active:
                    if svc == 'nginx':
                        runner('nginx', '-t', check=True)
                    runner('systemctl', 'restart', svc, check=True)
                else:
                    runner('systemctl', 'stop', svc, check=True)
            except Exception as se:
                action = 'restart' if was_active else 'stop'
                rollback_errors.append(f'Failed to {action} {svc}: {se}')

        if rollback_errors:
            raise RuntimeError(f"Rollback FAILED/incomplete: {'; '.join(rollback_errors)}. Pre-restore backup preserved at: {pre_backup_dir}. Original error: {exc}")
        if isinstance(exc, subprocess.CalledProcessError):
            cmd_name = exc.cmd[0] if isinstance(exc.cmd, list) else str(exc.cmd).split()[0]
            raise RuntimeError(f"Restore rolled back. Command '{cmd_name}' exited with {exc.returncode}.")
        raise RuntimeError('Restore rolled back: ' + str(exc))

def restore_archive(archive_path):
    if os.name == 'posix' and os.geteuid() != 0:
        raise RuntimeError('Restore requires root privileges.')

    lock_fd = acquire_shared_lock()
    old_umask = os.umask(0o077)

    try:
        with tempfile.TemporaryDirectory(prefix='hy2-restore-') as td:
            tdp = pathlib.Path(td)
            tdp.chmod(0o700)
            manifest = verify_archive(archive_path, extract_to=tdp)
            tcp_archived = archive_has_tcp(manifest)
            if not tcp_archived and any(pathlib.Path(p).exists() for p in TCP_FILES):
                raise RuntimeError('Old archive lacks existing TCP node; refuse partial restore.')

            current_mid_hash = get_machine_id_hash()
            source_mid_hash = manifest.get('source_machine_id_hash', '')
            if current_mid_hash == 'unknown' or current_mid_hash != source_mid_hash:
                raise RuntimeError('Different host machine detected. hy2-backup restore is strictly scoped to exact same-server configuration recovery; cross-host migration is not supported.')

            osinfo = dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
            if osinfo.get('ID','').strip('"') != 'ubuntu' or osinfo.get('VERSION_ID','').strip('"') not in ['22.04','24.04']:
                raise RuntimeError('Restore boundary: supported on Ubuntu 22.04/24.04 only.')
            if platform.machine() != 'x86_64' or not pathlib.Path('/run/systemd/system').exists():
                raise RuntimeError('Requires x86_64 and systemd.')

            for cmd in ['nginx', 'curl', 'systemctl', 'warp-cli']:
                if not shutil.which(cmd):
                    raise RuntimeError(f'Missing required system dependency: {cmd}. Restore requires existing dependencies on the same server; full OS/bare-metal bootstrap is not supported.')
            if not pathlib.Path('/lib/systemd/system/warp-svc.service').exists() and not pathlib.Path('/etc/systemd/system/warp-svc.service').exists():
                raise RuntimeError('Missing warp-svc.service. Restore requires existing dependencies on the same server; full OS/bare-metal bootstrap is not supported.')

            # Check destination ancestor symlinks before any mutations or UFW changes
            for mf in manifest['files']:
                rel_clean = mf['path'].lstrip('/')
                dest_p = pathlib.Path('/') / rel_clean
                cur = dest_p.parent
                while True:
                    if cur.is_symlink():
                        raise ValueError('Destination ancestor is a symlink: ' + str(cur))
                    if cur == pathlib.Path('/') or cur in pathlib.Path('/').parents or cur == cur.parent:
                        break
                    cur = cur.parent

            ssh_ports = set()
            if pathlib.Path('/usr/sbin/sshd').exists():
                try:
                    ssh_out = run('/usr/sbin/sshd', '-T', capture=True, check=False).stdout
                    for line in ssh_out.splitlines():
                        if line.startswith('port '):
                            ssh_ports.add(int(line.split()[1]))
                except Exception:
                    pass
            if os.environ.get('SSH_CONNECTION'):
                try:
                    ssh_ports.add(int(os.environ['SSH_CONNECTION'].split()[3]))
                except Exception:
                    pass
            if not ssh_ports:
                raise RuntimeError('Unable to safely determine current SSH ports; aborting before firewall configuration.')

            staged_bin = tdp / 'files/etc/hy2-node/sing-box'
            staged_conf = tdp / 'files/etc/hy2-node/config.json'
            staged_bin.chmod(0o755)

            try:
                conf_data = json.loads(staged_conf.read_text(encoding='utf-8'))
                check_conf_data = json.loads(json.dumps(conf_data))
                for ib in check_conf_data.get('inbounds', []):
                    if ib.get('type') == 'hysteria2':
                        tls = ib.get('tls', {})
                        cp = tls.get('certificate_path', '')
                        kp = tls.get('key_path', '')
                        if cp and cp.startswith('/'):
                            tls['certificate_path'] = str(tdp / ('files' + cp))
                        if kp and kp.startswith('/'):
                            tls['key_path'] = str(tdp / ('files' + kp))
                        break
                check_conf_file = tdp / 'check_config.json'
                check_conf_file.write_text(json.dumps(check_conf_data), encoding='utf-8')
                run(str(staged_bin), 'check', '-c', str(check_conf_file))
                if tcp_archived:
                    tcp_path = tdp / 'files/etc/hy2-tcp/config.json'
                    tcp_data = json.loads(tcp_path.read_text())
                    run(str(staged_bin), 'check', '-c', str(tcp_path))
                else: tcp_data = None
                sub_entries = [mf for mf in manifest['files'] if mf['path'].startswith('/var/lib/hy2-subscription/') and mf['type']=='file']
                if len(sub_entries) != 1: raise ValueError('Ambiguous subscription in archive.')
                validate_connections(conf_data,
                    json.loads((tdp/'files/etc/hy2-node/connection.json').read_text()),
                    (tdp/sub_entries[0]['archive_path']).read_text(), tcp_data,
                    json.loads((tdp/'files/etc/hy2-tcp/connection.json').read_text()) if tcp_archived else None)
                check_conf_file.unlink(missing_ok=True)
            except Exception as e:
                raise RuntimeError('Staged sing-box candidate validation failed: ' + str(e))

            if shutil.which('ufw'):
                for sp in ssh_ports:
                    run('ufw', 'allow', str(sp) + '/tcp', check=False)
                node_port = manifest.get('node', {}).get('port', 443)
                run('ufw', 'allow', '80/tcp', check=False)
                run('ufw', 'allow', '443/tcp', check=False)
                run('ufw', 'allow', str(node_port) + '/udp', check=False)

            stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
            pre_backup = pathlib.Path('/var/backups/hy2-oneclick') / ('pre-restore-' + stamp)

            def production_health_check():
                run('nginx', '-t', check=True)
                run('systemctl', 'restart', 'nginx', check=True)
                run('systemctl', 'daemon-reload', check=True)
                run('systemctl', 'restart', 'hy2-node', check=True)
                if tcp_archived:
                    run('systemctl', 'enable', 'hy2-tcp', check=True)
                    run('systemctl', 'restart', 'hy2-tcp', check=True)
                    run('systemctl', 'is-active', 'hy2-tcp', check=True)
                    backend = run('ss','-H','-lnt','sport = :18080',capture=True).stdout.splitlines()
                    if not backend or any(line.split()[3] != '127.0.0.1:18080' for line in backend):
                        raise RuntimeError('Restored TCP backend must listen on loopback only.')
                time.sleep(2)
                run('systemctl', 'is-active', 'hy2-node', check=True)

                node_port = manifest.get('node', {}).get('port', 443)
                listeners = run('ss', '-H', '-lnu', f'sport = :{node_port}', capture=True, check=True).stdout
                if not listeners.strip():
                    raise RuntimeError(f'HY2 node is not listening on UDP port {node_port}')

                warp_ok = False
                for _ in range(12):
                    r_warp = run('curl', '-fsS', '--max-time', '8', '--socks5-hostname', '127.0.0.1:40000',
                                 'https://www.cloudflare.com/cdn-cgi/trace', capture=True, check=False)
                    if r_warp.returncode == 0 and re.search(r'^warp=(on|plus)$', r_warp.stdout, re.M):
                        warp_ok = True
                        break
                    time.sleep(1)
                if not warp_ok:
                    raise RuntimeError('WARP local proxy health check failed: warp=(on|plus) not detected on 127.0.0.1:40000')

                conn_p = pathlib.Path('/etc/hy2-node/connection.json')
                sub_p = None
                for sname in ['subscription.txt', 'sub.txt']:
                    candidate_sub = pathlib.Path('/var/lib/hy2-subscription') / sname
                    if candidate_sub.exists():
                        sub_p = candidate_sub
                        break
                if conn_p.exists() and sub_p and sub_p.exists():
                    conn_info = json.loads(conn_p.read_text(encoding='utf-8'))
                    suburl = conn_info.get('subscription')
                    if suburl:
                        parsed_sub = urllib.parse.urlsplit(suburl)
                        sub_host = parsed_sub.hostname or '127.0.0.1'
                        sub_port = parsed_sub.port or 443
                        r_sub = run('curl', '-fsS', '--max-time', '15', '--noproxy', '*',
                                    '--resolve', f'{sub_host}:{sub_port}:127.0.0.1',
                                    suburl, capture=True, check=False)
                        if r_sub.returncode != 0:
                            raise RuntimeError(f'Subscription endpoint check failed with exit code {r_sub.returncode}')
                        expected_sub = sub_p.read_text(encoding='utf-8').strip()
                        if r_sub.stdout.strip() != expected_sub:
                            raise RuntimeError('Subscription endpoint content does not match subscription file.')

            execute_restore_transaction(
                dest_root=pathlib.Path('/'),
                manifest=manifest,
                staged_dir=tdp,
                pre_backup_dir=pre_backup,
                runner=run,
                health_check=production_health_check
            )

        print('\nRestore completed successfully.')
        print('Restored Domain/Host:', manifest.get('node', {}).get('domain'))
        print('Restored Port:', manifest.get('node', {}).get('port'))
        print('Services active and verified: hy2-node, nginx, warp-svc')
    finally:
        os.umask(old_umask)
        if lock_fd:
            try: lock_fd.close()
            except Exception: pass

def self_test():
    print('Running hy2-backup offline security tests...')
    with tempfile.TemporaryDirectory(prefix='hy2-test-') as td:
        tdp = pathlib.Path(td)

        def make_base_manifest(files):
            return {
                'manifest_version': '1.0',
                'created_at': '2026-10-11T00:00:00+00:00',
                'source_machine_id_hash': '0' * 64,
                'node': {'domain': 'node.example.com', 'port': 443},
                'files': files,
                'services': {}
            }

        trav_tar = tdp / 'trav.tar.gz'
        with tarfile.open(trav_tar, 'w:gz') as tar:
            data = b'malicious'
            ti = tarfile.TarInfo('files/etc/hy2-node/../../etc/shadow')
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        try:
            verify_archive(trav_tar)
            raise AssertionError('Failed to reject path traversal!')
        except ValueError:
            print('PASS: traversal attack rejected')

        abs_tar = tdp / 'abs.tar.gz'
        with tarfile.open(abs_tar, 'w:gz') as tar:
            data = b'malicious'
            ti = tarfile.TarInfo('/etc/shadow')
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        try:
            verify_archive(abs_tar)
            raise AssertionError('Failed to reject absolute path!')
        except ValueError:
            print('PASS: absolute path rejected')

        esc_tar = tdp / 'esc.tar.gz'
        with tarfile.open(esc_tar, 'w:gz') as tar:
            ti = tarfile.TarInfo('files/etc/hy2-node/evil_link')
            ti.type = tarfile.SYMTYPE
            ti.linkname = '../../../../etc/shadow'
            tar.addfile(ti)
        try:
            verify_archive(esc_tar)
            raise AssertionError('Failed to reject escaping symlink!')
        except ValueError:
            print('PASS: symlink escape rejected')

        parent_tar = tdp / 'parent.tar.gz'
        with tarfile.open(parent_tar, 'w:gz') as tar:
            ti_link = tarfile.TarInfo('files/etc/hy2-node/fake_dir')
            ti_link.type = tarfile.SYMTYPE
            ti_link.linkname = 'real_dir'
            tar.addfile(ti_link)
            data = b'child'
            ti_child = tarfile.TarInfo('files/etc/hy2-node/fake_dir/file.txt')
            ti_child.size = len(data)
            tar.addfile(ti_child, io.BytesIO(data))
        try:
            verify_archive(parent_tar)
            raise AssertionError('Failed to reject symlink parent directory!')
        except ValueError:
            print('PASS: symlink parent directory rejected')

        hash_tar = tdp / 'hash.tar.gz'
        with tarfile.open(hash_tar, 'w:gz') as tar:
            cfg = b'{"inbounds": [{"type": "hysteria2"}]}'
            ti_cfg = tarfile.TarInfo('files/etc/hy2-node/config.json')
            ti_cfg.size = len(cfg)
            tar.addfile(ti_cfg, io.BytesIO(cfg))
            m = make_base_manifest([
                {'path': '/etc/hy2-node/config.json', 'archive_path': 'files/etc/hy2-node/config.json',
                 'type': 'file', 'mode': '0600', 'size': len(cfg), 'sha256': '0' * 64}
            ])
            mb = json.dumps(m).encode('utf-8')
            tim = tarfile.TarInfo('manifest.json')
            tim.size = len(mb)
            tar.addfile(tim, io.BytesIO(mb))
        try:
            verify_archive(hash_tar)
            raise AssertionError('Failed to reject hash mismatch without extraction!')
        except ValueError:
            print('PASS: hash mismatch rejected before extraction')

        hl_tar = tdp / 'hl.tar.gz'
        with tarfile.open(hl_tar, 'w:gz') as tar:
            ti_hl = tarfile.TarInfo('files/etc/hy2-node/hardlink')
            ti_hl.type = tarfile.LNKTYPE
            ti_hl.linkname = 'files/etc/hy2-node/config.json'
            tar.addfile(ti_hl)
        try:
            verify_archive(hl_tar)
            raise AssertionError('Failed to reject hardlink!')
        except ValueError:
            print('PASS: hardlink rejected')

    print('ALL HY2-BACKUP SELF-TESTS PASSED.')

def main():
    parser = argparse.ArgumentParser(description='HY2 private backup and restore tool')
    subparsers = parser.add_subparsers(dest='command', help='Operation to execute')

    p_backup = subparsers.add_parser('backup', help='Create a private backup archive')
    p_backup.add_argument('--output', '-o', help='Path to output .tar.gz archive')

    p_verify = subparsers.add_parser('verify', help='Inspect and verify a backup archive')
    p_verify.add_argument('archive', help='Path to .tar.gz archive')

    p_restore = subparsers.add_parser('restore', help='Restore node configuration from a backup archive (same-server only)')
    p_restore.add_argument('archive', help='Path to .tar.gz archive')

    subparsers.add_parser('self-test', help='Run offline adversarial tests')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        if args.command == 'backup':
            create_backup(args.output)
        elif args.command == 'verify':
            verify_archive(args.archive)
        elif args.command == 'restore':
            restore_archive(args.archive)
        elif args.command == 'self-test':
            self_test()
    except Exception as e:
        sys.stderr.write('FAILED: ' + str(e) + '\n')
        sys.exit(1)

if __name__ == '__main__':
    main()
PY

#!/usr/bin/env bash
# HY2 + WARP installer. Ubuntu 22.04/24.04, x86_64, systemd.
# Usage: sudo bash install-hy2.sh --domain node.example.com --email you@example.com --accept-terms
set -euo pipefail
command -v python3 >/dev/null || { echo 'Please install python3 first: apt-get update && apt-get install -y python3' >&2; exit 1; }
exec python3 - "$@" <<'PY'
import argparse, base64, datetime, hashlib, io, ipaddress, json, os
import pathlib, platform, re, secrets, shutil, socket, subprocess, sys, tarfile
import tempfile, time, urllib.parse, urllib.request, uuid

try:
    import fcntl
except ImportError:
    fcntl = None

VERSION = '1.14.4'
SHA256 = '699a1b510aa4396b2176d32d1181920399ebf1e267835da6f3b598d0f7c24968'
BASE = pathlib.Path('/etc/hy2-node')
TCP = pathlib.Path('/etc/hy2-tcp')
TCP_UNIT = pathlib.Path('/etc/systemd/system/hy2-tcp.service')
STATE = pathlib.Path('/etc/hy2-oneclick/state.json')
SITE = pathlib.Path('/etc/nginx/sites-available/hy2-oneclick.conf')
ENABLED = pathlib.Path('/etc/nginx/sites-enabled/hy2-oneclick.conf')
SUB = pathlib.Path('/var/lib/hy2-subscription')
ACME = pathlib.Path('/var/lib/hy2-acme')
LOCK_PATH = pathlib.Path('/run/hy2-node.lock')

SUFFIXES = ['google.com', 'googleapis.com', 'muse.ai', 'meta.com', 'meta.ai',
            'facebook.com', 'facebook.net', 'fbcdn.net', 'instagram.com', 'cdninstagram.com',
            'youtube.com', 'youtu.be', 'youtube-nocookie.com', 'googlevideo.com', 'ytimg.com', 'ggpht.com']
HOSTS = ['gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com',
         'cloudaicompanion.googleapis.com', 'cloudcode-pa.googleapis.com',
         'daily-cloudcode-pa.googleapis.com', 'muse.ai', 'auth.muse.ai', 'auth.meta.com',
         'www.meta.com', 'meta.ai', 'www.meta.ai', 'facebook.com', 'www.facebook.com',
         'graph.facebook.com', 'instagram.com', 'www.instagram.com', 'i.instagram.com']
PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4',
           '240.0.0.0/4', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']

def run(*args, capture=False, check=True):
    return subprocess.run(args, text=True, check=check,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)

def write_atomic(path, content, mode=0o600):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content); stream.flush(); os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name): os.unlink(name)

def validate(domain, email, port, mode='domain'):
    if mode == 'ip':
        address = ipaddress.ip_address(domain)
        if address.version != 4 or not address.is_global:
            raise ValueError('No-domain mode requires the server public IPv4 address.')
    elif len(domain) > 253 or '.' not in domain or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in domain.split('.')):
        raise ValueError('Use a valid ASCII DNS hostname, e.g. node.example.com (no URL/path).')
    if mode == 'domain':
        try: ipaddress.ip_address(domain)
        except ValueError: pass
        else: raise ValueError('Use --ip for IP-address mode.')
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise ValueError('A valid Certbot contact email is required (not an expiry alert service).')
    if not isinstance(port, int) or (port != 443 and not (1024 <= port <= 65535 and port != 40000)):
        raise ValueError('HY2 UDP port must be 443 or 1024..65535, excluding 40000.')

def config(s):
    deny = {'ip_cidr': PRIVATE, 'action': 'reject'}
    rules = [deny, {'domain_suffix': ['localhost', 'local'], 'action': 'reject'},
             {'action': 'sniff', 'timeout': '500ms'},
             {'domain_suffix': SUFFIXES, 'network': 'udp', 'port': 443, 'action': 'reject'}]
    rules += [{'domain': [h], 'network': 'tcp', 'action': 'route',
               'outbound': 'warp-google', 'override_address': h} for h in HOSTS]
    rules += [{'domain_suffix': SUFFIXES, 'action': 'route', 'outbound': 'warp-google'},
              {'action': 'resolve', 'server': 'security-local'}, deny]
    cert = '/etc/letsencrypt/live/' + s['domain']
    return {'log': {'level': 'warn'},
            'dns': {'servers': [{'type': 'local', 'tag': 'security-local'}]},
            'inbounds': [{'type': 'hysteria2', 'tag': 'hy2', 'listen': '::',
                          'listen_port': s['port'],
                          'users': [{'name': 'v2rayN', 'password': s['password']}],
                          'tls': {'enabled': True, 'certificate_path': cert + '/fullchain.pem',
                                  'key_path': cert + '/privkey.pem'}}],
            'outbounds': [{'type': 'direct', 'tag': 'direct'},
                          {'type': 'socks', 'tag': 'warp-google', 'server': '127.0.0.1',
                           'server_port': 40000, 'version': '5'}],
            'route': {'rules': rules, 'final': 'direct'}}

def uri(s):
    return ('hysteria2://' + urllib.parse.quote(s['password'], safe='') + '@' + s['domain']
            + ':' + str(s['port']) + '/?' + urllib.parse.urlencode({'sni': s['domain']}) + '#HY2-WARP')

def ensure_tcp_state(s):
    if bool(s.get('tcp_uuid')) != bool(s.get('ws_path')):
        raise ValueError('Incomplete TCP identity in saved state.')
    if not s.get('tcp_uuid'):
        s.update(tcp_uuid=str(uuid.uuid4()), ws_path='/ws/' + secrets.token_urlsafe(24))
    uuid.UUID(s['tcp_uuid'])
    if not re.fullmatch(r'/ws/[A-Za-z0-9_-]{16,80}', s['ws_path']):
        raise ValueError('Invalid saved WebSocket path.')
    return s

def tcp_config(s):
    c = config(s)
    c['inbounds'] = [{'type': 'vless', 'tag': 'tcp-backup', 'listen': '127.0.0.1',
                      'listen_port': 18080, 'users': [{'uuid': s['tcp_uuid']}],
                      'transport': {'type': 'ws', 'path': s['ws_path']}}]
    return c

def tcp_uri(s):
    query = urllib.parse.urlencode({'encryption': 'none', 'security': 'tls', 'type': 'ws',
                                   'sni': s['domain'], 'host': s['domain'],
                                   'path': s['ws_path'], 'alpn': 'http/1.1'})
    return 'vless://' + s['tcp_uuid'] + '@' + s['domain'] + ':443?' + query + '#TCP-443-Backup'

def subscription(s):
    return uri(s) + '\n' + tcp_uri(s) + '\n'

def nginx(s, tls):
    domain = s['domain']
    text = ('server {\n listen 80;\n listen [::]:80;\n server_name ' + domain + ';\n'
            ' location ^~ /.well-known/acme-challenge/ { root /var/lib/hy2-acme; }\n'
            ' location / { return 404; }\n}\n')
    if tls:
        text += ('server {\n listen 443 ssl;\n listen [::]:443 ssl;\n server_name ' + domain + ';\n'
                 ' ssl_certificate /etc/letsencrypt/live/' + domain + '/fullchain.pem;\n'
                 ' ssl_certificate_key /etc/letsencrypt/live/' + domain + '/privkey.pem;\n'
                 ' ssl_protocols TLSv1.2 TLSv1.3;\n server_tokens off;\n'
                 ' location = /hy2/' + s['token'] + ' {\n'
                 '  alias /var/lib/hy2-subscription/sub.txt;\n'
                 '  default_type text/plain;\n  access_log off;\n'
                 '  add_header Cache-Control "no-store" always;\n }\n'
                 ' location = ' + s['ws_path'] + ' {\n'
                 '  proxy_pass http://127.0.0.1:18080;\n  proxy_http_version 1.1;\n'
                 '  proxy_set_header Upgrade $http_upgrade;\n'
                 '  proxy_set_header Connection "upgrade";\n  proxy_set_header Host $host;\n'
                 '  proxy_read_timeout 3600s;\n  proxy_send_timeout 3600s;\n  access_log off;\n }\n'
                 ' location / { return 404; }\n}\n')
    return text

def certificate_command(s, binary):
    target = ['--ip-address', s['domain'], '--preferred-profile', 'shortlived'] if s.get('mode') == 'ip' else ['-d', s['domain']]
    return [binary, 'certonly', '--webroot', '-w', str(ACME), '--cert-name', s['domain'],
            *target, '--email', s['email'], '--agree-tos', '--non-interactive', '--keep-until-expiring']

def self_test():
    s = {'domain': 'node.example.com', 'email': 'admin@example.com', 'port': 443,
         'password': 'test+/secret', 'token': 'a' * 48}
    ensure_tcp_state(s)
    validate(s['domain'], s['email'], s['port'])
    validate(s['domain'], s['email'], 24443)
    c = config(s); r = c['route']['rules']
    assert r[0]['ip_cidr'] == PRIVATE and r[-1]['ip_cidr'] == PRIVATE
    assert r[-2] == {'action': 'resolve', 'server': 'security-local'}
    assert c['route']['final'] == 'direct'
    assert c['outbounds'][1]['server'] == '127.0.0.1'
    assert {x['override_address'] for x in r if 'override_address' in x} == set(HOSTS)
    general = next(i for i,x in enumerate(r) if x.get('domain_suffix') == SUFFIXES and x.get('action') == 'route')
    assert all(i < general and x['domain'] == [x['override_address']] for i,x in enumerate(r) if 'override_address' in x)
    for bad in ['x;id.example.com', 'https://example.com', 'a..com', '-x.com', '127.0.0.1']:
        try: validate(bad, s['email'], 443)
        except ValueError: pass
        else: raise AssertionError('accepted bad domain: ' + bad)
    for bad_port in [0, -1, 80, 40000, 1023, 65536]:
        try: validate(s['domain'], s['email'], bad_port)
        except ValueError: pass
        else: raise AssertionError('accepted bad port: ' + str(bad_port))
    assert 'test%2B%2Fsecret' in uri(s) and 'insecure' not in uri(s)
    assert base64.b64decode(base64.b64encode((uri(s)+'\n').encode())).decode().strip() == uri(s)
    assert 'listen 443' not in nginx(s, False) and 'access_log off' in nginx(s, True)
    ip_s = dict(s, domain='8.8.8.8', mode='ip')
    validate(ip_s['domain'], ip_s['email'], ip_s['port'], 'ip')
    assert config(ip_s)['route'] == c['route']
    assert config(ip_s)['outbounds'] == c['outbounds']
    assert '@8.8.8.8:' in uri(ip_s) and 'insecure' not in uri(ip_s)
    assert '--ip-address' in certificate_command(ip_s, 'certbot')
    assert 'shortlived' in certificate_command(ip_s, 'certbot')
    assert '--ip-address' not in certificate_command(s, 'certbot')
    for bad_ip in ['127.0.0.1', '192.168.1.1', '169.254.169.254', '::1', 'example.com']:
        try: validate(bad_ip, s['email'], 443, 'ip')
        except ValueError: pass
        else: raise AssertionError('accepted invalid public IPv4')
    for address in ['127.0.0.1','169.254.169.254','10.0.0.1','::1','fe80::1']:
        assert any(ipaddress.ip_address(address) in ipaddress.ip_network(n) for n in PRIVATE)
    print('PASS: validation, default port 443, private routing, Google/Meta rules, subscription encoding, nginx templates')

def smoke_test(s, tcp=False):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0)); port=listener.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='hy2-smoke-') as td:
        path=pathlib.Path(td)/'client.json'
        client={'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port}],
                'outbounds':[{'type':'hysteria2','server':'127.0.0.1','server_port':s['port'],
                              'password':s['password'],'tls':{'enabled':True,'server_name':s['domain']}}]}
        if tcp:
            client['outbounds']=[{'type':'vless','server':'127.0.0.1','server_port':443,
                'uuid':s['tcp_uuid'],'tls':{'enabled':True,'server_name':s['domain'],'alpn':['http/1.1']},
                'transport':{'type':'ws','path':s['ws_path'],'headers':{'Host':s['domain']}}}]
        write_atomic(path,json.dumps(client))
        proc=subprocess.Popen([str(BASE/'sing-box'),'run','-c',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            for _ in range(30):
                if proc.poll() is not None: raise RuntimeError('HY2 smoke-test client failed to start.')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2): break
                except OSError: time.sleep(.2)
            else: raise RuntimeError('HY2 smoke-test listener did not start.')
            for url in ['https://www.youtube.com/','https://gemini.google.com/',
                        'https://muse.ai/','http://127.0.0.1:80/','http://169.254.169.254/']:
                r=run('curl','-sS','--max-time','20','--socks5-hostname','127.0.0.1:'+str(port),
                      '-o','/dev/null','-w','%{http_code}',url,capture=True,check=False)
                private=url.startswith('http:')
                if (not private and r.returncode!=0) or (private and r.returncode==0):
                    raise RuntimeError('HY2 connectivity/isolation check failed: '+url)
                print('PASS TCP:' if tcp else 'PASS HY2:',url, 'blocked' if private else 'HTTP '+r.stdout,flush=True)
            run('systemctl','is-active','hy2-node','warp-svc','nginx','fail2ban')
        finally:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()

def tcp_smoke_test(s):
    return smoke_test(s, tcp=True)

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

def preflight(args):
    if os.geteuid() != 0: raise RuntimeError('Run with sudo/root.')
    osinfo = dict(line.split('=',1) for line in pathlib.Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if osinfo.get('ID','').strip('"') != 'ubuntu' or osinfo.get('VERSION_ID','').strip('"') not in ['22.04','24.04']:
        raise RuntimeError('Supported: fresh Ubuntu 22.04/24.04 only.')
    if platform.machine() != 'x86_64' or not pathlib.Path('/run/systemd/system').exists():
        raise RuntimeError('Requires x86_64 and systemd.')
    if not args.accept_terms: raise RuntimeError('Read README and add --accept-terms for Let\'s Encrypt and WARP terms.')
    existing = STATE.exists()
    if existing:
        s = json.loads(STATE.read_text())
        s.setdefault('mode','domain')
        if s.get('installer') != 'hy2-oneclick-v1': raise RuntimeError('Unrecognized installation state.')
        if args.domain and args.domain.lower() != s['domain']: raise RuntimeError('Reruns cannot change domain.')
        if args.ip and (s['mode'] != 'ip' or args.ip != s['domain']): raise RuntimeError('Reruns cannot change mode/IP.')
        if args.domain and s['mode'] != 'domain': raise RuntimeError('Reruns cannot change mode.')
        if args.port is not None and args.port != s['port']: raise RuntimeError('Reruns cannot change port.')
        if args.email and args.email != s['email']: raise RuntimeError('Reruns cannot change email.')
    else:
        port = 443 if args.port is None else args.port
        s = {'installer': 'hy2-oneclick-v1', 'mode': 'ip' if args.ip else 'domain', 'domain': (args.domain or args.ip or '').lower(),
             'email': args.email or '', 'port': port,
             'password': secrets.token_urlsafe(32), 'token': secrets.token_hex(24)}
        for p in [BASE, TCP, TCP_UNIT, SITE, pathlib.Path('/etc/systemd/system/hy2-node.service'), pathlib.Path('/var/lib/cloudflare-warp'), SUB, ACME, pathlib.Path('/etc/systemd/system/hy2-cert-renew.service')]:
            if p.exists(): raise RuntimeError('Existing unmanaged installation: ' + str(p))
        for proto,port_num in [('tcp',80),('tcp',443),('tcp',40000),('tcp',18080),('udp',s['port'])]:
            lines = run('ss', '-H', '-lnt' if proto=='tcp' else '-lnu', 'sport = :' + str(port_num), capture=True).stdout
            if lines.strip(): raise RuntimeError('Port already in use: '+str(port_num)+'/'+proto)
        enabled = pathlib.Path('/etc/nginx/sites-enabled')
        if enabled.exists() and any(enabled.iterdir()): raise RuntimeError('Existing nginx sites; use a fresh server.')
    if existing and not s.get('tcp_uuid'):
        if TCP.exists() or TCP_UNIT.exists():
            raise RuntimeError('Unmanaged TCP backup exists; use backup/restore, do not overwrite it.')
        if run('ss','-H','-lnt','sport = :18080',capture=True).stdout.strip():
            raise RuntimeError('TCP backend port 18080 is already in use.')
    ensure_tcp_state(s)
    validate(s['domain'], s['email'], s['port'], s['mode'])
    if s['mode']=='domain': socket.getaddrinfo(s['domain'],443)
    ssh = run('/usr/sbin/sshd','-T',capture=True).stdout
    ports = {int(line.split()[1]) for line in ssh.splitlines() if line.startswith('port ')}
    if os.environ.get('SSH_CONNECTION'): ports.add(int(os.environ['SSH_CONNECTION'].split()[3]))
    if args.ssh_port: ports.add(args.ssh_port)
    if not ports or any(not 1 <= p <= 65535 for p in ports): raise RuntimeError('Cannot determine SSH ports safely.')
    s['ssh_ports'] = sorted(ports)
    return s, existing, osinfo['VERSION_CODENAME'].strip('"')

def install(args):
    lock_fd = acquire_shared_lock()
    try:
        s,existing,codename = preflight(args)
        os.umask(0o077)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')
        backup = pathlib.Path('/var/backups/hy2-oneclick') / stamp
        backup.mkdir(parents=True, mode=0o700)

        # Pre-mutation snapshot of all owned files with full relative paths and original state
        managed_paths = [
            STATE,
            BASE / 'config.json',
            BASE / 'sing-box',
            BASE / 'connection.json',
            TCP / 'config.json',
            TCP / 'connection.json',
            TCP_UNIT,
            SITE,
            ENABLED,
            pathlib.Path('/etc/nginx/sites-enabled/default'),
            SUB / 'sub.txt',
            SUB / 'subscription.txt',
            pathlib.Path('/etc/systemd/system/hy2-node.service'),
            pathlib.Path('/etc/systemd/system/hy2-cert-renew.service'),
            pathlib.Path('/etc/systemd/system/hy2-cert-renew.timer'),
            pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/50-hy2-nginx'),
            pathlib.Path('/etc/fail2ban/jail.d/hy2-oneclick.local'),
            pathlib.Path('/etc/apt/apt.conf.d/20auto-upgrades'),
        ]

        snapshot_state = []
        for p in managed_paths:
            bk_target = backup / ('files' + str(p))
            if p.is_symlink():
                bk_target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.symlink(os.readlink(p), bk_target)
                snapshot_state.append({'path': p, 'existed': True, 'type': 'symlink', 'link_target': os.readlink(p)})
            elif p.is_file():
                bk_target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(p, bk_target)
                snapshot_state.append({'path': p, 'existed': True, 'type': 'file', 'mode': p.stat().st_mode})
            else:
                snapshot_state.append({'path': p, 'existed': False})

        was_active = (run('systemctl', 'is-active', 'hy2-node', capture=True, check=False).returncode == 0) if existing else False
        tcp_was_active = (run('systemctl', 'is-active', 'hy2-tcp', capture=True, check=False).returncode == 0) if existing else False
        tcp_was_enabled = (run('systemctl', 'is-enabled', 'hy2-tcp', capture=True, check=False).returncode == 0) if existing else False
        nginx_was_active = (run('systemctl', 'is-active', 'nginx', capture=True, check=False).returncode == 0) if existing else False

        write_atomic(STATE, json.dumps(s, indent=2))
        STATE.parent.chmod(0o700)
        print('Backup directory:', backup, flush=True)

        os.environ.update(DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
        run('apt-get','update','-qq')
        run('apt-get','install','-y','ca-certificates','curl','gnupg','nginx','certbot','ufw',
            'fail2ban','unattended-upgrades','dnsutils')
        certbot = '/usr/bin/certbot'
        if s['mode'] == 'ip':
            run('apt-get','install','-y','python3-venv')
            run('python3','-m','venv','/opt/hy2-certbot')
            run('/opt/hy2-certbot/bin/pip','install','--upgrade','certbot>=5.4,<6')
            certbot = '/opt/hy2-certbot/bin/certbot'

        for port in s['ssh_ports']: run('ufw','allow',str(port)+'/tcp')
        for port in ['80/tcp','443/tcp',str(s['port'])+'/udp']: run('ufw','allow',port)
        run('ufw','default','deny','incoming');run('ufw','default','allow','outgoing')
        run('ufw','--force','enable')
        write_atomic('/etc/fail2ban/jail.d/hy2-oneclick.local',
                     '[sshd]\nenabled = true\nbackend = systemd\nport = '+','.join(map(str,s['ssh_ports']))+
                     '\nmaxretry = 6\nfindtime = 600\nbantime = 3600\n')
        run('fail2ban-client','-t');run('systemctl','enable','--now','fail2ban');run('systemctl','restart','fail2ban')
        write_atomic('/etc/apt/apt.conf.d/20auto-upgrades','APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n',0o644)
        run('systemctl','enable','--now','apt-daily.timer','apt-daily-upgrade.timer')

        with tempfile.TemporaryDirectory() as td:
            k = pathlib.Path(td)/'key.gpg'
            run('curl','-fsSL','--retry','3','-o',str(k),'https://pkg.cloudflareclient.com/pubkey.gpg')
            run('gpg','--batch','--yes','--dearmor','--output','/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg',str(k))
        pathlib.Path('/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg').chmod(0o644)
        write_atomic('/etc/apt/sources.list.d/cloudflare-client.list',
                     'deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ '+codename+' main\n',0o644)
        run('apt-get','update','-qq');run('apt-get','install','-y','cloudflare-warp')
        run('systemctl','enable','--now','warp-svc')
        for _ in range(30):
            if run('warp-cli','--accept-tos','status',capture=True,check=False).returncode == 0: break
            time.sleep(1)
        if run('warp-cli','--accept-tos','registration','show',capture=True,check=False).returncode != 0:
            run('warp-cli','--accept-tos','registration','new',capture=True)
        run('warp-cli','--accept-tos','mode','proxy')
        run('warp-cli','--accept-tos','proxy','port','40000')
        run('warp-cli','--accept-tos','connect')

        trace = ''
        for _ in range(12):
            result=run('curl','-fsS','--max-time','8','--socks5-hostname','127.0.0.1:40000',
                       'https://www.cloudflare.com/cdn-cgi/trace',capture=True,check=False)
            trace=result.stdout
            if result.returncode == 0 and re.search(r'^warp=(on|plus)$',trace,re.M): break
            time.sleep(2)
        else: raise RuntimeError('WARP is not usable; stopping before deployment. Fix connectivity and rerun.')
        listeners=run('ss','-H','-lnt','sport = :40000',capture=True).stdout.splitlines()
        if not listeners or any(line.split()[3] not in ['127.0.0.1:40000','[::1]:40000'] for line in listeners):
            raise RuntimeError('WARP proxy must listen on loopback only.')
        print('WARP trace:', '; '.join(x for x in trace.splitlines() if x.startswith(('loc=','warp='))),flush=True)

        ACME.mkdir(parents=True,exist_ok=True);ACME.chmod(0o755)

        # Capture daemon and timer states before candidate deployment
        was_active = (run('systemctl', 'is-active', 'hy2-node', capture=True, check=False).returncode == 0)
        nginx_was_active = (run('systemctl', 'is-active', 'nginx', capture=True, check=False).returncode == 0)
        certbot_timer_existed = pathlib.Path('/lib/systemd/system/certbot.timer').exists() or pathlib.Path('/etc/systemd/system/certbot.timer').exists()
        certbot_timer_enabled = (run('systemctl', 'is-enabled', 'certbot.timer', capture=True, check=False).returncode == 0) if certbot_timer_existed else False
        certbot_timer_active = (run('systemctl', 'is-active', 'certbot.timer', capture=True, check=False).returncode == 0) if certbot_timer_existed else False
        hy2_timer_existed = pathlib.Path('/etc/systemd/system/hy2-cert-renew.timer').exists()
        hy2_timer_enabled = (run('systemctl', 'is-enabled', 'hy2-cert-renew.timer', capture=True, check=False).returncode == 0) if hy2_timer_existed else False
        hy2_timer_active = (run('systemctl', 'is-active', 'hy2-cert-renew.timer', capture=True, check=False).returncode == 0) if hy2_timer_existed else False

        # Protected candidate preparation and deployment flow
        candidate = BASE/'sing-box.new'
        candidate_config = BASE/'config.candidate.json'
        candidate_tcp_config = TCP/'config.candidate.json'
        try:
            certpath = pathlib.Path('/etc/letsencrypt/live') / s['domain']
            write_atomic(SITE, nginx(s, (certpath/'fullchain.pem').exists()))
            default = pathlib.Path('/etc/nginx/sites-enabled/default')
            if default.is_symlink(): default.unlink()
            if not ENABLED.exists(): ENABLED.symlink_to(SITE)
            run('nginx','-t');run('systemctl','enable','--now','nginx');run('systemctl','reload','nginx')
            run(*certificate_command(s,certbot))

            if s['mode'] == 'ip':
                write_atomic('/etc/systemd/system/hy2-cert-renew.service',
                             '[Unit]\nDescription=Renew HY2 short-lived IP certificate\nAfter=network-online.target nginx.service\n'
                             '[Service]\nType=oneshot\nExecStart=/opt/hy2-certbot/bin/certbot renew --quiet --no-random-sleep-on-renew\nTimeoutStartSec=1200\n',0o644)
                write_atomic('/etc/systemd/system/hy2-cert-renew.timer',
                             '[Unit]\nDescription=Hourly check for short-lived IP certificate renewal\n[Timer]\nOnCalendar=hourly\nRandomizedDelaySec=300\nPersistent=true\n[Install]\nWantedBy=timers.target\n',0o644)
                run('systemctl','daemon-reload')
                run('systemctl','disable','--now','certbot.timer')
                run('systemctl','enable','--now','hy2-cert-renew.timer')
            else:
                run('systemctl','enable','--now','certbot.timer')

            hook='#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/bin/systemctl reload nginx\n'
            if s['mode']=='ip':
                hook += 'if /bin/systemctl is-active --quiet hy2-node; then /bin/systemctl restart hy2-node; fi\n'
            write_atomic('/etc/letsencrypt/renewal-hooks/deploy/50-hy2-nginx',hook,0o700)

            # Download and validate sing-box core candidate
            BASE.mkdir(exist_ok=True);BASE.chmod(0o700)
            TCP.mkdir(exist_ok=True);TCP.chmod(0o700)
            with tempfile.TemporaryDirectory() as td:
                archive = pathlib.Path(td)/'sing-box.tar.gz'
                run('curl','-fL','--retry','3','--max-time','180','-o',str(archive),
                    'https://github.com/SagerNet/sing-box/releases/download/v'+VERSION+'/sing-box-'+VERSION+'-linux-amd64.tar.gz')
                data=archive.read_bytes()
                if hashlib.sha256(data).hexdigest()!=SHA256: raise RuntimeError('Official core checksum mismatch.')
                with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as t:
                    members=[m for m in t.getmembers() if m.isfile() and m.name.endswith('/sing-box')]
                    if len(members)!=1: raise RuntimeError('Unexpected release archive.')
                    candidate.write_bytes(t.extractfile(members[0]).read());candidate.chmod(0o755)

            write_atomic(candidate_config, json.dumps(config(s), indent=2))
            run(str(candidate), 'check', '-c', str(candidate_config))
            write_atomic(candidate_tcp_config, json.dumps(tcp_config(s), indent=2))
            run(str(candidate), 'check', '-c', str(candidate_tcp_config))

            service='''[Unit]
Description=Hysteria 2 with selective WARP routing
After=network-online.target warp-svc.service
Wants=network-online.target warp-svc.service
[Service]
ExecStart=/etc/hy2-node/sing-box run -c /etc/hy2-node/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''
            write_atomic('/etc/systemd/system/hy2-node.service', service, 0o644)
            write_atomic(TCP_UNIT, service.replace('Hysteria 2 with selective WARP routing',
                         'VLESS WebSocket TCP backup with selective WARP routing').replace(
                         '-c /etc/hy2-node/config.json', '-c /etc/hy2-tcp/config.json'), 0o644)
            # Stop hy2-node before replacing binary to prevent Linux ETXTBSY
            run('systemctl', 'stop', 'hy2-node', check=False)
            run('systemctl', 'stop', 'hy2-tcp', check=False)
            os.replace(candidate, BASE/'sing-box')
            os.replace(candidate_config, BASE/'config.json')
            os.replace(candidate_tcp_config, TCP/'config.json')

            run('systemctl','daemon-reload')
            run('systemctl','enable','hy2-node')
            run('systemctl','enable','hy2-tcp')
            run('systemctl','restart','hy2-tcp')
            run('systemctl','restart','hy2-node')
            time.sleep(2);run('systemctl','is-active','hy2-node')

            SUB.mkdir(exist_ok=True);SUB.chmod(0o750);shutil.chown(SUB,user='root',group='www-data')
            write_atomic(SUB/'sub.txt', base64.b64encode(subscription(s).encode()).decode()+'\n', 0o640)
            shutil.chown(SUB/'sub.txt',user='root',group='www-data')
            write_atomic(SITE, nginx(s, True));run('nginx','-t');run('systemctl','reload','nginx')
            suburl='https://'+s['domain']+'/hy2/'+s['token']

            fetched=run('curl','-fsS','--noproxy','*','--resolve',s['domain']+':443:127.0.0.1',suburl,capture=True).stdout
            if base64.b64decode(fetched).decode()!=subscription(s): raise RuntimeError('Subscription verification failed.')
            write_atomic(BASE/'connection.json', json.dumps({'uri':uri(s),'subscription':suburl},indent=2))
            write_atomic(TCP/'connection.json', json.dumps({'uri':tcp_uri(s),'subscription':suburl},indent=2))
            run('systemctl','is-active','hy2-node','hy2-tcp','warp-svc','nginx','fail2ban')
            tcp_smoke_test(s)
            smoke_test(s)
            if s['mode']=='ip':
                run(certbot,'renew','--dry-run','--cert-name',s['domain'],'--non-interactive','--no-random-sleep-on-renew')
        except Exception as deploy_err:
            sys.stderr.write('Deployment/verification failed; rolling back owned files...\n')
            sys.stderr.write('Note: Rollback restores prior managed core/config/service and subscription/nginx files. This does NOT undo package installations, UFW rules, or whole-system changes.\n')

            rollback_errors = []
            try:
                run('systemctl', 'stop', 'hy2-tcp', check=False)
                if not tcp_was_enabled: run('systemctl', 'disable', 'hy2-tcp', check=False)
            except Exception as e:
                rollback_errors.append(f'Failed to stop TCP candidate: {e}')

            # 1. Stop hy2-node with check to avoid leaving broken runtime
            try:
                run('systemctl', 'stop', 'hy2-node', check=True)
            except Exception as e:
                rollback_errors.append(f'Failed to stop hy2-node: {e}')

            # 2. Stop/disable any newly introduced timer units before unit files are removed
            if not hy2_timer_existed:
                try:
                    if run('systemctl', 'is-active', 'hy2-cert-renew.timer', capture=True, check=False).returncode == 0:
                        run('systemctl', 'stop', 'hy2-cert-renew.timer', check=True)
                    if run('systemctl', 'is-enabled', 'hy2-cert-renew.timer', capture=True, check=False).returncode == 0:
                        run('systemctl', 'disable', 'hy2-cert-renew.timer', check=True)
                except Exception as e:
                    rollback_errors.append(f'Failed to stop/disable temporary hy2-cert-renew.timer: {e}')

            # 3. Roll back owned files atomically
            for rb in snapshot_state:
                p = rb['path']
                bk_p = backup / ('files' + str(p))
                try:
                    if rb['existed']:
                        if rb['type'] == 'symlink':
                            p.unlink(missing_ok=True)
                            os.symlink(rb['link_target'], p)
                        elif rb['type'] == 'file':
                            temp_rb = p.with_name(p.name + '.rb')
                            shutil.copy2(bk_p, temp_rb)
                            if 'mode' in rb:
                                try: temp_rb.chmod(rb['mode'])
                                except Exception: pass
                            os.replace(temp_rb, p)
                    else:
                        # File was newly created during this run; remove it
                        if not existing and p == STATE:
                            # On first install, retain state.json to allow resumable rerun after fixing error
                            pass
                        else:
                            p.unlink(missing_ok=True)
                except Exception as e:
                    rollback_errors.append(f'Failed to restore {p}: {e}')

            for c in [candidate, candidate_config, candidate_tcp_config]:
                if c.exists():
                    try: c.unlink()
                    except Exception: pass

            try:
                run('systemctl', 'daemon-reload', check=True)
            except Exception as e:
                rollback_errors.append(f'systemctl daemon-reload failed: {e}')

            # 4. Restore certificate timers to prior enabled and active states for originally existing units only
            if certbot_timer_existed:
                try:
                    if certbot_timer_enabled:
                        run('systemctl', 'enable', 'certbot.timer', check=True)
                    else:
                        run('systemctl', 'disable', 'certbot.timer', check=True)
                    if certbot_timer_active:
                        run('systemctl', 'start', 'certbot.timer', check=True)
                    else:
                        run('systemctl', 'stop', 'certbot.timer', check=True)
                except Exception as e:
                    rollback_errors.append(f'Failed to restore certbot.timer state: {e}')

            if hy2_timer_existed:
                try:
                    if hy2_timer_enabled:
                        run('systemctl', 'enable', 'hy2-cert-renew.timer', check=True)
                    else:
                        run('systemctl', 'disable', 'hy2-cert-renew.timer', check=True)
                    if hy2_timer_active:
                        run('systemctl', 'start', 'hy2-cert-renew.timer', check=True)
                    else:
                        run('systemctl', 'stop', 'hy2-cert-renew.timer', check=True)
                except Exception as e:
                    rollback_errors.append(f'Failed to restore hy2-cert-renew.timer state: {e}')

            # 5. Restore daemons to prior active/inactive states
            try:
                if tcp_was_enabled: run('systemctl', 'enable', 'hy2-tcp', check=True)
                if tcp_was_active: run('systemctl', 'restart', 'hy2-tcp', check=True)
            except Exception as e:
                rollback_errors.append(f'Failed to restore TCP daemon state: {e}')
            try:
                if was_active:
                    run('systemctl', 'restart', 'hy2-node', check=True)
                else:
                    run('systemctl', 'stop', 'hy2-node', check=True)
            except Exception as e:
                rollback_errors.append(f'Failed to restore hy2-node daemon state: {e}')

            try:
                if nginx_was_active:
                    run('nginx', '-t', check=True)
                    run('systemctl', 'restart', 'nginx', check=True)
                else:
                    run('systemctl', 'stop', 'nginx', check=True)
            except Exception as e:
                rollback_errors.append(f'Failed to restore nginx daemon state: {e}')

            if rollback_errors:
                raise RuntimeError(f"Rollback FAILED/incomplete: {'; '.join(rollback_errors)}. Pre-deployment backup preserved at: {backup}. Original error: {deploy_err}")

            if isinstance(deploy_err, subprocess.CalledProcessError):
                cmd_name = deploy_err.cmd[0] if isinstance(deploy_err.cmd, list) else str(deploy_err.cmd).split()[0]
                raise RuntimeError(f"Deploy failed. Command '{cmd_name}' exited with status {deploy_err.returncode}.")
            raise deploy_err

        print('\nInstallation complete. Keep these links private:\n\nHY2 URI:\n'+uri(s)+
              '\n\nTCP backup URI:\n'+tcp_uri(s)+'\n\nV2RayN subscription:\n'+suburl)
        print('\nSaved in /etc/hy2-node/connection.json. No automatic reboot. WARP does not guarantee a country or account access.')
        if pathlib.Path('/var/run/reboot-required').exists(): print('OS reports reboot required; schedule it manually.')
    finally:
        if lock_fd:
            try: lock_fd.close()
            except Exception: pass

def main():
    parser=argparse.ArgumentParser(description='Fresh-server HY2 + selective WARP installer')
    choice=parser.add_mutually_exclusive_group()
    choice.add_argument('--domain',help='Use your DNS hostname')
    choice.add_argument('--ip',help='No domain: use your server public IPv4 with a trusted IP certificate')
    parser.add_argument('--email');parser.add_argument('--port',type=int)
    parser.add_argument('--ssh-port',type=int,help='Additional SSH port to preserve in firewall')
    parser.add_argument('--accept-terms',action='store_true',help='Accept Let\'s Encrypt and Cloudflare WARP terms')
    parser.add_argument('--self-test',action='store_true',help='Offline tests only; no installation')
    parser.add_argument('--plan',action='store_true',help='Validate inputs and print redacted configuration; no installation')
    args=parser.parse_args()
    try:
        if args.self_test: self_test()
        elif args.plan:
            port = 443 if args.port is None else args.port
            s={'mode':'ip' if args.ip else 'domain','domain':(args.domain or args.ip or '').lower(),'email':args.email or '', 'port':port,'password':'GENERATED_ON_SERVER','token':'GENERATED_ON_SERVER'}
            ensure_tcp_state(s)
            s['tcp_uuid']='00000000-0000-4000-8000-000000000001'
            s['ws_path']='/ws/GENERATED_ON_SERVER'
            validate(s['domain'],s['email'],s['port'],s['mode'])
            print(json.dumps({'hy2':config(s),'tcp_backup':tcp_config(s),'nginx':nginx(s,True)},indent=2))
        else:
            if not args.domain and not args.ip and not STATE.exists():
                with open('/dev/tty','r+') as tty:
                    def ask(prompt):
                        tty.write(prompt);tty.flush()
                        answer=tty.readline()
                        if not answer: raise RuntimeError('No terminal input; use --domain or --ip flags.')
                        return answer.strip()
                    mode=ask('选择安装模式：1=有自己的域名，2=没有域名（公网 IPv4）：')
                    if mode=='1': args.domain=ask('域名：')
                    elif mode=='2': args.ip=ask('这台服务器的公网 IPv4：')
                    else: raise ValueError('Please choose 1 or 2.')
                    if not args.email: args.email=ask('Certbot 联系邮箱（不用于到期提醒）：')
                    if not args.accept_terms:
                        args.accept_terms=ask('同意 Let\'s Encrypt 与 WARP 条款？输入 yes 继续：')=='yes'
            install(args)
    except Exception as e:
        if isinstance(e,subprocess.CalledProcessError):
            cmd_name = e.cmd[0] if isinstance(e.cmd, list) else str(e.cmd).split()[0]
            print(f'FAILED: command {cmd_name} exited {e.returncode}. Fix the error above and rerun.', file=sys.stderr)
        else:
            print('FAILED: '+str(e), file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
PY

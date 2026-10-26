"""Check dual-node identity, routing, and refusal of incomplete TCP snapshots."""
import base64
import copy
from pathlib import Path


def load(name):
    path = Path(__file__).parent / name
    source = path.read_text(encoding='utf-8').split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    scope = {'__name__': 'offline_tcp_review'}
    exec(compile(source, str(path), 'exec'), scope)
    return scope


def main():
    install, backup = load('install-hy2.sh'), load('hy2-backup.sh')
    state = {'domain': 'node.example.com', 'mode': 'domain', 'email': 'admin@example.com',
             'port': 443, 'password': 'synthetic+/password', 'token': 'a' * 48}
    install['ensure_tcp_state'](state)
    identity = copy.deepcopy(state)
    install['ensure_tcp_state'](state)
    assert identity == state, 'rerun_rotated_credentials'
    encoded = base64.b64encode(install['subscription'](state).encode()).decode()
    hy2, tcp = install['config'](state), install['tcp_config'](state)
    hy2_conn, tcp_conn = {'uri': install['uri'](state)}, {'uri': install['tcp_uri'](state)}
    validate = backup['validate_connections']
    validate(hy2, hy2_conn, encoded, tcp, tcp_conn)
    for mode in ('domain', 'ip'):
        s = dict(state, mode=mode, domain='node.example.com' if mode=='domain' else '8.8.8.8')
        assert install['tcp_config'](s)['route'] == install['config'](s)['route']
        website = install['nginx'](s, True)
        assert 'location = ' + s['ws_path'] in website
        assert 'proxy_pass http://127.0.0.1:18080;' in website
    for domain in ('youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'ggpht.com'):
        assert domain in install['SUFFIXES']
    legacy = base64.b64encode((hy2_conn['uri']+'\n').encode()).decode()
    validate(hy2, hy2_conn, legacy)
    for kind in ('wrong_uuid', 'wrong_path', 'public_backend', 'routing_drift', 'missing_tcp_uri'):
        bad_tcp = copy.deepcopy(tcp)
        bad_conn = copy.deepcopy(tcp_conn)
        if kind == 'wrong_uuid': bad_tcp['inbounds'][0]['users'][0]['uuid']='00000000-0000-4000-8000-000000000001'
        if kind == 'wrong_path': bad_tcp['inbounds'][0]['transport']['path']='/wrong'
        if kind == 'public_backend': bad_tcp['inbounds'][0]['listen']='0.0.0.0'
        if kind == 'routing_drift': bad_tcp['route']['final']='warp-google'
        if kind == 'missing_tcp_uri': bad_conn={}
        try: validate(hy2, hy2_conn, encoded, bad_tcp, bad_conn)
        except ValueError: pass
        else: raise AssertionError(kind + '_accepted')
    paths = backup['TCP_FILES']
    assert backup['archive_has_tcp']({'files':[{'path': p} for p in paths]})
    assert not backup['archive_has_tcp']({'files':[]})
    for omitted in paths:
        try: backup['archive_has_tcp']({'files':[{'path':p} for p in paths if p!=omitted]})
        except ValueError: pass
        else: raise AssertionError('partial_tcp_archive_accepted')
    print('PASS: dual-node templates, stable credentials, YouTube rules, legacy compatibility and eight refusal cases')


if __name__ == '__main__':
    main()

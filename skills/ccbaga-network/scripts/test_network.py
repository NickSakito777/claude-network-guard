#!/usr/bin/env python3
# [INPUT]: 本 Skill 执行层、临时密钥/配置和可丢弃本机子进程。
# [OUTPUT]: URL、配对/权限、host-key 固定、服务器快照、路由源码不变量、注入边界和失败回归。
# [POS]: 安装后即可运行的标准库离线验收；不读取用户配置、不连接 VPS，也不证明客户端网络行为。
# [PROTOCOL]: 变更时更新此头部，然后检查 CLAUDE.md
import ast
import importlib.util
import json
import io
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('network', Path(__file__).with_name('network.py'))
n = importlib.util.module_from_spec(spec); spec.loader.exec_module(n)


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ccbaga-skill-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_fixed_provider_destinations(self):
        self.assertEqual(n.provider_url('dmit'), 'https://www.dmit.io/aff.php?aff=28800')
        self.assertEqual(n.provider_url('webshare'), 'https://www.webshare.io/?referral_code=qlm1mt9xibc9')

    def test_deploy_payload_is_read_as_utf8(self):
        payload = (n.SKILL/'scripts/setup-vps.sh').read_text(encoding='utf-8')
        self.assertIn('CCBAGA_PREFLIGHT_APPROVED', payload)
        self.assertIn("'CCBAGA_PREFLIGHT_APPROVED': '1'", Path(n.__file__).read_text())
        start = payload.index('python3 - "$NEW_CONF" <<\'PY\'\n') + len('python3 - "$NEW_CONF" <<\'PY\'\n')
        end = payload.index('\nPY\nxray run -test', start)
        ast.parse(payload[start:end])
        self.assertIn('set -euo pipefail', payload)
        self.assertIn('CCBAGA_NETWORK_MANAGED=1', payload)
        self.assertIn('# CCBaga Network managed SSH hardening', payload)
        self.assertIn('# CCBaga Network managed subscription service', payload)
        self.assertIn('# CCBaga Network managed subscription hardening', payload)
        self.assertIn('"network": "udp", "outboundTag": "block"', payload)
        self.assertIn('"network": "tcp", "outboundTag": "home"', payload)
        self.assertIn('ipv6: false', payload)
        self.assertIn('udp: false', payload)
        self.assertIn('IP-CIDR,223.5.5.5/32,DIRECT,no-resolve', payload)
        self.assertIn('proxies: [${NODE_NAME}, REJECT]', payload)
        self.assertIn('"servers": ["https://1.1.1.1/dns-query"]', payload)
        self.assertNotIn('https+local://1.1.1.1/dns-query', payload)
        self.assertIn("export DIRECT_DOMAINS=' '", n.exports(self.config()))

    def test_host_identity_requires_out_of_band_fingerprint_before_ssh(self):
        pem = self.root/'host'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(pem)],check=True)
        key_type, blob = pem.with_suffix('.pub').read_text().split()[:2]
        candidate = {'host':'vps.example.com','type':key_type,'blob':blob,
                     'fingerprint':n.key_fingerprint(key_type,blob)}
        config_path = self.root/'connection.json'
        legacy_hosts = self.root/'known_hosts'
        legacy_hosts.write_text('existing-known-hosts-receipt\n')
        legacy_content = legacy_hosts.read_bytes()

        with patch.object(n, 'scan_host_keys', return_value=[candidate]), patch.object(n, 'execute') as remote:
            output = io.StringIO()
            with redirect_stdout(output):
                n.identity(self.config(), pem, config_path)
            remote.assert_not_called()
        self.assertIn(candidate['fingerprint'], output.getvalue())
        self.assertIn('No SSH authentication or server command was sent', output.getvalue())
        self.assertNotIn(blob, output.getvalue())
        pin = self.root/'known_hosts.pinned'
        self.assertFalse(pin.exists())
        with patch.object(n, 'scan_host_keys', return_value=[candidate]):
            with self.assertRaises(ValueError):
                n.pin_host_key(self.config(), config_path, 'SHA256:provider-mismatch')
        self.assertFalse(pin.exists())

        with patch.object(n, 'scan_host_keys', return_value=[candidate]), \
             patch.object(n, 'execute', return_value='ROOT=verified; OS=12') as remote:
            output = io.StringIO()
            with redirect_stdout(output):
                n.identity(self.config(), pem, config_path, candidate['fingerprint'])
            self.assertIn('StrictHostKeyChecking=yes', remote.call_args.args[0])
            self.assertNotIn('accept-new', remote.call_args.args[0])
        self.assertEqual(pin.read_text(), f"{candidate['host']} {candidate['type']} {candidate['blob']}\n")
        self.assertEqual(pin.stat().st_mode & 0o777, 0o600)
        self.assertIn('SSH_HOST_KEY_VERIFIED=' + candidate['fingerprint'], output.getvalue())
        self.assertEqual(legacy_hosts.read_bytes(), legacy_content)

        other = self.root/'other-host'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(other)],check=True)
        other_type, other_blob = other.with_suffix('.pub').read_text().split()[:2]
        replacement = {'host':candidate['host'],'type':other_type,'blob':other_blob,
                       'fingerprint':n.key_fingerprint(other_type,other_blob)}
        original = pin.read_bytes()
        with patch.object(n, 'scan_host_keys', return_value=[replacement]):
            with self.assertRaises(ValueError):
                n.pin_host_key(self.config(), config_path, replacement['fingerprint'])
        self.assertEqual(pin.read_bytes(), original)

    def test_host_key_scan_uses_openssh_without_exposing_raw_scan_output(self):
        pem = self.root/'host'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(pem)],check=True)
        key_type, blob = pem.with_suffix('.pub').read_text().split()[:2]
        real_run = subprocess.run
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if args[0] == '/stub/ssh-keyscan':
                return subprocess.CompletedProcess(args, 0, f'vps.example.com {key_type} {blob}\n# warning\n', '')
            return real_run(args, **kwargs)

        with patch.object(n, 'program', side_effect=lambda name: '/stub/ssh-keyscan' if name == 'ssh-keyscan' else shutil.which(name)), \
             patch.object(n.subprocess, 'run', side_effect=run):
            records = n.scan_host_keys('vps.example.com')
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]['fingerprint'], n.key_fingerprint(key_type, blob))
        self.assertTrue(any(Path(call[0]).name == 'ssh-keygen' and call[1:3] == ['-E', 'sha256'] for call in calls))
        self.assertEqual(calls[0], ['/stub/ssh-keyscan', '-T', '10', '-p', '22', 'vps.example.com'])

    def test_route_following_dns_preserves_ip_or_hostname_proxy_bootstrap(self):
        payload = (n.SKILL/'scripts/setup-vps.sh').read_text(encoding='utf-8')
        for home_host in ['203.0.113.10', 'proxy.example.net']:
            conf = {**self.config(), 'home_host':home_host}
            n.validate_config(conf)
            self.assertIn(f'export HOME_HOST={home_host}\n', n.exports(conf))
        self.assertIn('"address": e["HOME_HOST"]', payload)
        self.assertIn('"servers": ["https://1.1.1.1/dns-query"]', payload)
        self.assertNotIn('https+local://1.1.1.1/dns-query', payload)

    def test_server_snapshot_is_fixed_sanitized_and_classifies_conflicts(self):
        self.assertNotIn('cat "$path"', n.SERVER_SNAPSHOT)
        bash = self.bash_program()
        syntax = subprocess.run([bash, '-n'], input=n.SERVER_SNAPSHOT, text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        first = {
            'CC_PORT_443':'free','CC_PORT_8443':'free','CC_XRAY_UNIT':'absent','CC_SUB_UNIT':'absent',
            'CC_NFTABLES_UNIT':'absent','CC_STATE_FILE':'absent','CC_UFW':'inactive',
            'CC_SSH_DROPIN':'absent','CC_SUB_UNIT_FILE':'absent','CC_SUB_HARDENING':'absent',
            'CC_XRAY_CONFIG':'absent','CC_SUB_DIR':'absent',
        }
        output = ''.join(f'{key}={value}\n' for key,value in first.items())
        parsed = n.parse_server_snapshot(output)
        self.assertEqual(n.classify_server_snapshot(parsed), 'first-deploy')
        rerun = {**first,'CC_STATE_FILE':'managed','CC_XRAY_UNIT':'active',
                 'CC_PORT_443':'ccbaga','CC_PORT_8443':'ccbaga','CC_SUB_UNIT':'active',
                 'CC_NFTABLES_UNIT':'inactive','CC_UFW':'active',
                 'CC_SSH_DROPIN':'managed','CC_SUB_UNIT_FILE':'managed','CC_SUB_HARDENING':'managed',
                 'CC_XRAY_CONFIG':'present','CC_SUB_DIR':'present'}
        self.assertEqual(n.classify_server_snapshot(rerun), 'same-product-rerun')
        for unit in ['CC_XRAY_UNIT', 'CC_SUB_UNIT']:
            self.assertEqual(n.classify_server_snapshot({**rerun, unit:'unknown'}), 'other-service-conflict')
        conflict = {**first,'CC_PORT_443':'other'}
        self.assertEqual(n.classify_server_snapshot(conflict), 'other-service-conflict')
        firewall_conflict = {**first,'CC_UFW':'active'}
        self.assertEqual(n.classify_server_snapshot(firewall_conflict), 'other-service-conflict')
        ssh_conflict = {**first,'CC_SSH_DROPIN':'other'}
        self.assertEqual(n.classify_server_snapshot(ssh_conflict), 'other-service-conflict')
        legacy = {**first,'CC_STATE_FILE':'legacy-unverified','CC_XRAY_CONFIG':'present'}
        self.assertEqual(n.classify_server_snapshot(legacy), 'other-service-conflict')
        with self.assertRaises(ValueError):
            n.parse_server_snapshot(output + 'CC_PASSWORD=do-not-return\n')

    def snapshot_function(self, name):
        return name + '() {' + n.SERVER_SNAPSHOT.split(name + '() {', 1)[1].split('\n}\n', 1)[0] + '\n}\n'

    def test_server_unit_read_failure_and_transition_are_not_absence(self):
        mock = '''systemctl() {
          if [ "$4" = LoadState ]; then value="$TEST_UNIT_LOAD"; else value="$TEST_UNIT_ACTIVE"; fi
          [ "$value" != FAIL ] || return 1
          printf '%s\\n' "$value"
        }\n'''
        script = mock + self.snapshot_function('unit_state') + 'unit_state xray.service'
        for load, active, expected in [
            ('FAIL', '', 'unknown'), ('not-found', '', 'absent'),
            ('loaded', 'active', 'active'), ('loaded', 'inactive', 'inactive'),
            ('loaded', 'failed', 'failed'), ('loaded', 'FAIL', 'unknown'),
            ('loaded', 'activating', 'unknown'), ('loaded', 'deactivating', 'unknown'),
            ('bad-setting', 'active', 'unknown'),
        ]:
            result = subprocess.run([self.bash_program(), '-c', script], text=True, capture_output=True,
                env={**os.environ, 'TEST_UNIT_LOAD':load, 'TEST_UNIT_ACTIVE':active}, check=True)
            self.assertEqual(result.stdout, expected)

    def test_port_read_failure_is_not_a_free_port(self):
        script = 'ss() { return 1; };\n' + self.snapshot_function('port_owner') + 'port_owner 443 xray.service'
        result = subprocess.run([self.bash_program(), '-c', script], text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, 'unknown')

    def test_firewall_read_failure_is_not_inactive(self):
        script = "ufw() { printf 'Status: inactive\\n'; return 1; };\n" + self.snapshot_function('ufw_state') + 'ufw_state'
        result = subprocess.run([self.bash_program(), '-c', script], text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, 'unknown')

    def bash_program(self):
        if os.name != 'nt':
            return '/bin/bash'
        candidates = [
            Path(os.environ.get('ProgramFiles', r'C:\Program Files'))/'Git/bin/bash.exe',
            Path(os.environ.get('ProgramFiles', r'C:\Program Files'))/'Git/usr/bin/bash.exe',
            Path(os.environ.get('LOCALAPPDATA', ''))/'Programs/Git/bin/bash.exe',
        ]
        git = shutil.which('git')
        if git:
            git_root = Path(git).resolve().parent.parent
            candidates.extend([git_root/'usr/bin/bash.exe', git_root/'bin/bash.exe'])
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
        found = shutil.which('bash') or shutil.which('bash.exe')
        if found:
            return found
        self.skipTest('Git Bash is required for the quoted-stdin shell boundary test')

    def test_real_key_pairing_private_copy_and_cleanup(self):
        pem = self.root/'id_rsa.pem'; pub = self.root/'id_rsa.pub'; ppk = self.root/'id_rsa.ppk'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(pem)],check=True)
        (self.root/'id_rsa.pem.pub').rename(pub)
        algorithm, blob = pub.read_text().split()[:2]
        ppk.write_text(f'PuTTY-User-Key-File-3: {algorithm}\nPublic-Lines: 1\n{blob}\nPrivate-Lines: 1\nfixture\n')
        conf = {'pem':str(pem),'ppk':str(ppk),'pub':str(pub)}
        pem.chmod(0o644)
        with n.Key(conf) as key:
            n.win.assert_private(key) if os.name == 'nt' else self.assertEqual(key.stat().st_mode & 0o777,0o600)
            self.assertEqual(key.read_bytes(),pem.read_bytes())
            copy = key
        self.assertFalse(copy.exists())
        if os.name != 'nt': self.assertEqual(pem.stat().st_mode & 0o777,0o644)
        ppk.write_text(f'PuTTY-User-Key-File-3: {algorithm}\nPublic-Lines: 1\nAAAA\n')
        with self.assertRaises(ValueError): n.Key(conf)
        with self.assertRaises(ValueError): n.key_data(None,str(ppk),str(pub))

    def config(self):
        return {'vps':'vps.example.com','home_host':'203.0.113.1','home_port':5328,
                'expected_ip':'203.0.113.1','home_user':'fixture-user','home_pass':'fixture-secret',
                'pem':'/tmp/id_rsa.pem','ppk':'/tmp/id_rsa.ppk','pub':'/tmp/id_rsa.pub'}

    def test_config_is_private_and_rejects_link_or_command_host(self):
        conf = self.config(); path = self.root/'connection.json'
        n.private_write(path,json.dumps(conf)); self.assertEqual(n.read_config(path),conf)
        with self.assertRaises(FileExistsError): n.private_write(path,'overwrite')
        if os.name == 'nt': subprocess.run(['icacls',str(path),'/grant','*S-1-1-0:(R)'],check=True,capture_output=True)
        else: path.chmod(0o644)
        with self.assertRaises((ValueError,OSError)): n.read_config(path)
        link = self.root/'linked.json'; link.symlink_to(path)
        with self.assertRaises(ValueError): n.read_config(link)
        for host in ['-oProxyCommand=id','user@host','host;id','ssh://host','host\nwhoami']:
            self.assertFalse(n.host_valid(host))
        self.assertTrue(n.host_valid('2001:db8::1'))

    def test_agent_configuration_needs_no_terminal_and_never_prints_secrets(self):
        path = self.root/'private/connection.json'
        n.configure(path, io.StringIO(json.dumps(self.config())))
        self.assertEqual(n.read_config(path), self.config())
        n.win.assert_private(path) if os.name == 'nt' else self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(FileExistsError): n.configure(path, io.StringIO(json.dumps(self.config())))
        for conf in [{}, {**self.config(), 'home_port': 0}, {**self.config(), 'pem': None}]:
            invalid = self.root/'invalid.json'
            with self.assertRaises(ValueError): n.configure(invalid, io.StringIO(json.dumps(conf)))
            self.assertFalse(invalid.exists())
        with self.assertRaises(ValueError): n.configure(path, io.StringIO(' ' * 65537))
        repo = self.root/'project'; repo.mkdir(); (repo/'.git').mkdir()
        with self.assertRaises(ValueError): n.configure(repo/'connection.json', io.StringIO(json.dumps(self.config())))
        result = subprocess.run([sys.executable, str(n.SKILL/'scripts/network.py'), 'configure', '--config', str(self.root/'cli/connection.json')],
                                input=json.dumps(self.config()), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(self.config()['home_pass'], result.stdout + result.stderr)

    def test_credentials_travel_only_in_quoted_stdin(self):
        conf = self.config(); marker = self.root/'injected'
        conf['home_pass'] = "p'$(touch " + str(marker) + ')'
        bash = self.bash_program()
        out = n.execute([bash,'-s'],n.exports(conf)+'printf %s "$HOME_PASS"\n')
        self.assertEqual(out,conf['home_pass']); self.assertFalse(marker.exists())
        args = n.ssh_args(conf,Path('/tmp/key'),self.root/'connection.json')
        self.assertNotIn(conf['home_pass'],' '.join(args))
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn('GlobalKnownHostsFile=' + os.devnull,args)
        self.assertIn('known_hosts.pinned', ' '.join(args))
        self.assertNotIn('accept-new',args)
        self.assertIn('IdentityAgent=none',args)
        curl = n.curl_config(conf)
        self.assertIn(json.dumps(conf['home_user']+':'+conf['home_pass']),curl)

    def test_failed_or_timed_out_process_never_returns_success(self):
        with self.assertRaises(RuntimeError): n.execute([sys.executable,'-c','raise SystemExit(1)'])
        with self.assertRaises(RuntimeError): n.execute([sys.executable,'-c','import time;time.sleep(5)'],timeout=.05)
        output = n.execute([sys.executable,'-c','print("x"*100000,end="")'])
        self.assertEqual(len(output),65536)

    def test_subscription_requires_expected_host_and_complete_success_marker(self):
        link = 'http://example.com:8443/'+'a'*32+'/clash.yaml'
        self.assertEqual(n.subscription('CC_SUB_URL='+link+'\n','example.com'),link)
        for output in ['partial setup', 'CC_SUB_URL='+link.replace('example.com','other.com'), 'CC_SUB_URL='+link+'?injected=1']:
            with self.assertRaises(ValueError): n.subscription(output,'example.com')
        ipv6 = 'http://[2001:db8::1]:8443/'+'b'*32+'/clash.yaml'
        self.assertEqual(n.subscription('CC_SUB_URL='+ipv6,'2001:0db8::1'),ipv6)


if __name__ == '__main__':
    unittest.main()

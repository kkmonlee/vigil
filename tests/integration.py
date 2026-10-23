import os
from pathlib import Path
import select
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / 'zig-out/bin/agent'
HELPER = ROOT / 'zig-out/bin/helper'
SOCKET = Path('/run/vigil/helper.sock')


def run(*args, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, timeout=15, **kwargs)
    if result.returncode:
        raise AssertionError(f'{args!r} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}')
    return result


def nft(script):
    return run('nft', '-f', '-', input=script)


def table(name):
    return run('nft', '-s', 'list', 'table', 'inet', name).stdout


def policy(name, cidr):
    return f'''sourceSets:
  {name}: ["{cidr}"]
services:
  ssh:
    listeners:
      - {{port: 22, proto: tcp}}
rules:
  - allow: {{sources: ["{name}"], service: "ssh"}}
defaults:
  inbound: deny
  outbound: allow
'''


def compile_policy(path):
    result = run(str(AGENT), '--policy', str(path), '--show-compiled')
    return result.stderr[result.stderr.index('add table inet vigilfw'):]


def as_uid(uid):
    def drop():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
    return drop


CLIENT = '''import socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect(sys.argv[1])
payload = sys.argv[2].encode()
frame = struct.pack('!I', len(payload)) + payload
for byte in frame:
    s.sendall(bytes([byte]))
reply = b''
while len(reply) < 2:
    chunk = s.recv(2 - len(reply))
    if not chunk: break
    reply += chunk
print(reply.decode())
'''


def request(script, uid):
    return run('python3', '-c', CLIENT, str(SOCKET), script, preexec_fn=as_uid(uid)).stdout.strip()


def unauthorized_request(uid):
    client = 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1]); print(s.recv(2).decode())'
    return run('python3', '-c', client, str(SOCKET), preexec_fn=as_uid(uid)).stdout.strip()


def wait_until(check, message):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.05)
    raise AssertionError(message)


def wait_for_watcher(process):
    log = bytearray()
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if select.select([process.stderr], [], [], 0.05)[0]:
            chunk = os.read(process.stderr.fileno(), 4096)
            if not chunk:
                break
            log.extend(chunk)
            if b'Policy watcher started for' in log:
                return log.decode()
    raise AssertionError('Watcher did not start:\n' + log.decode())


def main():
    if not Path('/.dockerenv').exists() or os.geteuid() != 0:
        raise SystemExit('Use the documented disposable Docker container; do not run against a host firewall.')
    nft('table inet unrelated {\n chain keep {\n ip saddr 198.51.100.1 accept\n }\n}\n')
    unrelated = table('unrelated')
    example = compile_policy(ROOT / 'config/policy.yml')
    run('nft', '-c', '-f', '-', input=example)
    assert table('unrelated') == unrelated
    print('PASS: bundled IPv4/IPv6 and rate-limit example passes nft validation', flush=True)
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        directory.chmod(0o755)
        first = directory / 'first.yml'
        second = directory / 'second.yml'
        first.write_text(policy('old_lan', '192.0.2.0/24'))
        second.write_text(policy('new_lan', '203.0.113.0/24'))
        first_script = compile_policy(first)
        second_script = compile_policy(second)

        nft(first_script)
        assert 'old_lan' in table('vigilfw')
        nft(second_script)
        nft(second_script)  # Reapplying must not accumulate objects or rules.
        current = table('vigilfw')
        assert 'new_lan' in current and 'old_lan' not in current
        assert table('unrelated') == unrelated
        failed = subprocess.run(['nft', '-f', '-'], input=first_script + '\nadd rule inet vigilfw missing_chain accept\n', text=True, capture_output=True)
        assert failed.returncode != 0
        assert table('vigilfw') == current and table('unrelated') == unrelated
        print('PASS: first install, repeated replacement, stale-set removal, unrelated-table preservation and atomic rollback', flush=True)

        env = dict(os.environ, VIGIL_AGENT_UID='1000')
        helper = subprocess.Popen([str(HELPER)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        agent = None
        try:
            wait_until(SOCKET.exists, 'Helper socket was not created')
            info = SOCKET.stat()
            assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 1000
            duplicate = subprocess.run([str(HELPER)], env=env, capture_output=True, timeout=5)
            assert duplicate.returncode != 0 and SOCKET.exists()
            assert request(first_script, 1000) == 'OK'
            assert 'old_lan' in table('vigilfw')
            # Test peer checks independently of socket permissions.
            SOCKET.chmod(0o666)
            assert unauthorized_request(1001) == 'FA'
            assert 'old_lan' in table('vigilfw')
            SOCKET.chmod(0o600)
            assert request('invalid nft syntax\n', 1000) == 'FA'
            assert 'old_lan' in table('vigilfw')
            assert request(second_script, 1000) == 'OK'
            assert table('unrelated') == unrelated
            print('PASS: authorized and unauthorized peers, socket permissions, duplicate helper refusal and apply failures', flush=True)

            data = Path('/var/lib/vigil')
            data.mkdir(parents=True, exist_ok=True)
            os.chown(data, 1000, 1000)
            agent = subprocess.Popen([str(AGENT), '--policy', str(first), '--no-observer', '--no-health-api', '--watch'], preexec_fn=as_uid(1000), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            wait_until(lambda: 'old_lan' in table('vigilfw'), 'Zig agent did not apply its policy through the C helper')
            startup_log = wait_for_watcher(agent)
            first.write_text(second.read_text())
            wait_until(lambda: 'new_lan' in table('vigilfw') and 'old_lan' not in table('vigilfw'), 'Watcher did not replace its policy through the helper')
            agent.send_signal(signal.SIGTERM)
            _, log = agent.communicate(timeout=8)
            assert agent.returncode == 0, startup_log + log
            agent = None
            assert table('unrelated') == unrelated
            print('PASS: unprivileged Zig agent to root C helper, live policy reload and clean shutdown', flush=True)
        finally:
            if agent is not None and agent.poll() is None:
                agent.kill()
                agent.communicate()
            helper.terminate()
            helper.communicate(timeout=5)
            assert not SOCKET.exists(), 'Helper did not remove its socket on shutdown'
            SOCKET.unlink(missing_ok=True)

        missing = subprocess.run([str(AGENT), '--policy', str(first), '--no-observer', '--no-health-api'], preexec_fn=as_uid(1000), capture_output=True, timeout=5)
        assert missing.returncode != 0, 'Agent reported success without a helper'
        print('PASS: missing helper fails startup', flush=True)

        unsafe = directory / 'unsafe'
        unsafe.mkdir(mode=0o777)
        unsafe.chmod(0o777)
        bad = subprocess.run([str(HELPER)], env=dict(env, VIGIL_SOCKET_PATH=str(unsafe / 'helper.sock')), capture_output=True, timeout=5)
        assert bad.returncode != 0
        sentinel = directory / 'sentinel'
        sentinel.write_text('keep')
        bad = subprocess.run([str(HELPER)], env=dict(env, VIGIL_SOCKET_PATH=str(sentinel)), capture_output=True, timeout=5)
        assert bad.returncode != 0 and sentinel.read_text() == 'keep'
        print('PASS: unsafe runtime directory and existing file refusal', flush=True)

    print('All Linux integration checks passed.', flush=True)


if __name__ == '__main__':
    main()

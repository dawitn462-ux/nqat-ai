import subprocess
import time

t = time.time()
try:
    r = subprocess.run(
        ['nuclei.exe', '-target', 'http://localhost:3000', '-tags', 'cve,misconfiguration,exposure', '-timeout', '10', '-jsonl', '-silent'],
        capture_output=True,
        text=True,
        cwd=r'C:\Users\hp\Downloads\web-vuln-platform',
        timeout=30
    )
    print('Took:', time.time() - t)
    print('STDOUT:', r.stdout)
    print('STDERR:', r.stderr)
except subprocess.TimeoutExpired as e:
    print('Timed out after', time.time() - t)
    print('Partial STDOUT:', e.stdout)
    print('Partial STDERR:', e.stderr)
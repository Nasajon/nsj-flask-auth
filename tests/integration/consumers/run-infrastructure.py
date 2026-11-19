"""Stop/recover only this harness's Redis and authority; preserve nonce volume."""
from pathlib import Path
import subprocess
import time
ROOT=Path(__file__).resolve().parent
base=['docker','compose','-f',str(ROOT/'.local/compose.json')]
def run(*args):subprocess.run([*base,*args],check=True)
def phase(name):run('exec','-T','client','python','/fixture/infrastructure.py',name)
try:
    run('stop','redis');phase('redis-down')
finally:run('start','redis')
time.sleep(2);phase('redis-up')
try:
    run('stop','authority')
    print('Waiting 32 seconds to exhaust all authority/profile caches',flush=True)
    time.sleep(32);phase('authority-down')
finally:run('start','authority')
time.sleep(2);phase('authority-up')

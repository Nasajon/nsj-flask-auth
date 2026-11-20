"""Inspect logs without printing credentials or unsanitized failures."""
import json
from pathlib import Path
import subprocess
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent
config = json.loads((ROOT / '.local/config.json').read_text())
base = ['docker', 'compose', '-f', str(ROOT / '.local/compose.json')]
for app in ['atendimento', 'erp', 'roteirizacao', 'estoque', 'tesouraria', 'authority']:
    data = subprocess.check_output([*base, 'logs', '--no-color', app], stderr=subprocess.STDOUT).decode(errors='replace')
    for _ in range(5):
        assert all(key.lower() not in data.lower() for key in config['keys'].values()), app + ': credential found in log'
        data = unquote(data)
    print(app + ': no full credential in logs (five decoding passes)')
violations = subprocess.check_output([*base, 'exec', '-T', 'postgres', 'psql', '-U', 'fixture', '-d', 'service_account_smoke', '-Atc', 'SELECT count(*) FROM fixture.violations']).decode().strip()
assert violations == '0', 'Incoming key reached a non-authority transport'
print('No incoming service-account key reached profile/OAuth/Multidb')
data = subprocess.check_output([*base, 'logs', '--no-color', 'postgres'], stderr=subprocess.STDOUT).decode(errors='replace')
assert 'sa_77@business47' in data, 'No own-account SQL connection observed'
assert 'forbidden_default_must_never_be_used@' not in data
print('Observed own-account SQL connection; no default credential connection')

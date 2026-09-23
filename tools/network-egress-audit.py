#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
from urllib.parse import urlsplit
import re

ROOTS = [Path('app/src/main/java'), Path('core/src/main/kotlin')]
ALLOWED = {
    'feodotracker.abuse.ch', 'www.spamhaus.org', 'cinsscore.com',
    'lists.blocklist.de', 'rules.emergingthreats.net', 'raw.githubusercontent.com',
    'iplists.firehol.org', 'check.torproject.org', 'github.com', 'paypal.me',
    'release-assets.githubusercontent.com', 'objects.githubusercontent.com',
}
URL = re.compile(r'https?://[^"\s)<>]+')
hosts: set[str] = set()
violations: list[str] = []
for root in ROOTS:
    for path in root.rglob('*'):
        if not path.is_file() or path.suffix not in {'.kt', '.kts', '.java'}:
            continue
        text = path.read_text(errors='strict')
        # Redirect destinations are runtime egress too even when they appear as explicit host
        # allowlist literals rather than full source URLs. Account for them in the same inventory.
        for redirect_host in ('release-assets.githubusercontent.com', 'objects.githubusercontent.com'):
            if f'"{redirect_host}"' in text:
                hosts.add(redirect_host)
        for raw in URL.findall(text):
            parsed = urlsplit(raw.rstrip('.,;'))
            if parsed.scheme != 'https':
                violations.append(f'{path}: non-HTTPS runtime URL: {raw}')
                continue
            host = (parsed.hostname or '').lower()
            if not host or host not in ALLOWED:
                violations.append(f'{path}: undocumented runtime host: {host or raw}')
            else:
                hosts.add(host)

doc = Path('NETWORK-EGRESS.md').read_text()
for host in sorted(hosts):
    if f'`{host}`' not in doc:
        violations.append(f'NETWORK-EGRESS.md: missing host {host}')
for host in sorted(ALLOWED - hosts):
    violations.append(f'allowlist contains unused host: {host}')
if violations:
    raise SystemExit('NETWORK_EGRESS_FAIL\n' + '\n'.join(violations))
print(f'NETWORK_EGRESS_PASS hosts={len(hosts)}')

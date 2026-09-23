#!/usr/bin/env python3
# STATUS: DIAMANT VGT SUPREME
from pathlib import Path
import re

root = Path('.')
repo = (root / 'app/src/main/java/de/visiongaia/gedefense/mobile/AsnEvidenceRepository.kt').read_text()
index = (root / 'core/src/main/kotlin/de/visiongaia/gedefense/mobile/core/AsnLiteIndex.kt').read_text()
runtime = (root / 'app/src/main/java/de/visiongaia/gedefense/mobile/AppRuntime.kt').read_text()
flow = (root / 'app/src/main/java/de/visiongaia/gedefense/mobile/FullFlowAnalytics.kt').read_text()
job = (root / 'app/src/main/java/de/visiongaia/gedefense/mobile/ThreatIntelJobService.kt').read_text()
version = (root / 'VERSION').read_text().strip()
version_code = (root / 'VERSION_CODE').read_text().strip()
build = (root / 'app/build.gradle.kts').read_text()

failures: list[str] = []
def require(ok: bool, message: str) -> None:
    if not ok:
        failures.append(message)

require(version == '0.27.8-beta.6', 'VERSION changed during ASN evidence block')
require(version_code == '55', 'VERSION_CODE changed during ASN evidence block')
require('versionCode = 55' in build and 'versionName = "0.27.8-beta.6"' in build, 'Gradle release metadata changed')

for marker in (
    'SOURCE_ID = "sapics-ip-location-db/iptoasn-asn"',
    'UPSTREAM_ID = "IPtoASN"',
    'LICENSE_ID = "PDDL-1.0"',
    'EVIDENCE_CLASS = "evidence_only"',
    'iptoasn-asn-ipv4.csv',
    'iptoasn-asn-ipv6.csv',
    'iptoasn-asn-ipv4.csv.sha256',
    'iptoasn-asn-ipv6.csv.sha256',
    'v4SourceSha256',
    'v6SourceSha256',
    'v4IndexSha256',
    'upstreamId',
    'v6IndexSha256',
    'organizationsSha256',
    'AsnLiteCompiler.compile',
    'AsnLiteIndex.open',
):
    require(marker in repo, f'ASN repository invariant missing: {marker}')
require('db-ip' not in repo.lower() and 'dbip' not in repo.lower(), 'DB-IP ASN source reference remains in ASN repository')
require('MessageDigest.isEqual' in repo, 'constant-time ASN hash/MAC comparison missing')
require('Proxy.NO_PROXY' in repo, 'ASN snapshot downloader must bypass ambient proxy configuration')
require('Destination addresses are\n * never sent to an ASN service' in repo, 'local-only ASN lookup invariant documentation missing')

for marker in (
    'MAGIC_V4', 'MAGIC_V6', 'MAGIC_ORG',
    'V4_RECORD_BYTES = 24', 'V6_RECORD_BYTES = 48',
    'IpPrefix.parseAddress', 'java.lang.Long.compareUnsigned',
    'if (row.asn == 0L) continue',
    'while (low <= high)',
    'organizationOffsets',
):
    require(marker in index, f'ASN binary-index invariant missing: {marker}')

require('val asnEvidence by lazy' in runtime, 'AppRuntime ASN repository ownership missing')
require('launchEnrichment("asn-evidence-cache") { asnEvidence.loadCached() }' in runtime, 'ASN cached bootstrap missing')
require('try { asnEvidence.syncDue() }' in runtime, 'initial feed sync ASN refresh missing')
require('runtime.asnEvidence.syncDue()' in job, 'periodic ASN refresh missing')
require('upstream=${asn.upstreamId}' in job and 'v4_index_sha256=' in job and 'org_index_sha256=' in job, 'ASN sync evidence lacks complete provenance/index hashes')
require('"asn.sync"' in job and 'evidence_only=true' in job, 'ASN sync provenance evidence missing')

helper_match = re.search(r'private fun emitAsnEvidence\(.*?\n    }\n\n    private fun notifyUi', flow, re.S)
require(helper_match is not None, 'ASN flow evidence helper missing')
if helper_match:
    helper = helper_match.group(0)
    require('runtime.asnEvidence.lookup(destination)' in helper, 'ASN flow lookup missing')
    require('upstream=${snapshot.upstreamId}' in helper, 'ASN upstream provenance missing from flow evidence')
    require('type = "network.asn"' in helper, 'ASN evidence event missing')
    require('source_sha256=' in helper and 'index_sha256=' in helper and 'evidence_only=true' in helper, 'ASN evidence provenance/hash marker missing')
    require('runtime.xdr.' not in helper, 'ASN evidence must not enter XDR scoring')
    require('destination=' not in helper and 'subject = "AS${asn.asn}"' in helper, 'ASN evidence must avoid raw destination IP persistence')
require('emitAsnEvidence(owner, dst)' in flow, 'ASN enrichment not connected to Full Flow open events')

security = (root / 'tools/security-audit.sh').read_text()
release = (root / 'tools/release-readiness.sh').read_text()
doc = (root / 'ASN-EVIDENCE.md').read_text()
require('python3 tools/asn-evidence-audit.py' in security, 'security audit does not include ASN audit')
require('bash tools/security-audit.sh' in release, 'release readiness no longer chains security audit')
require('ASN-EVIDENCE.md' in release, 'release readiness does not require ASN provenance document')
for marker in ('IPtoASN', 'PDDL-1.0', 'source SHA-256', 'compiled IPv4/IPv6 index SHA-256', 'evidence_only'):
    require(marker in doc, f'ASN provenance document missing: {marker}')

if failures:
    raise SystemExit('ASN_EVIDENCE_AUDIT_FAIL\n' + '\n'.join(failures))
print('ASN_EVIDENCE_AUDIT_PASS source=IPtoASN license=PDDL-1.0 families=IPv4+IPv6 evidence_only=true')

#!/usr/bin/env python3
"""Stage-2 deterministic compiler for GeDefense Mobile Privacy Intelligence TSV.

Ingests audited local baseline rules plus optional licensed upstream wildcard/hosts feeds,
enforces the license corridor, blocks dangerous vendor-apex / ESSENTIAL collisions,
collapses redundant child domains via a reverse-label suffix trie, and stays bounded
below the 8,192-rule GaiaNet binary limit.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

MAX_PARSER_RULES = 8192
ALLOWED_LICENSES = {'MIT', 'Apache-2.0', 'MPL-2.0', 'LGPL-3.0', 'GPL-3.0', 'REFERENCE'}
FORBIDDEN_LICENSE_TOKENS = ('CC-BY-NC', 'CC BY-NC', 'PROPRIETARY', 'ODBL', 'AGPL', 'MCRAE', 'UNKNOWN')
VALID_CATEGORIES = {
    'ADS',
    'ANALYTICS',
    'DEVICE_TELEMETRY',
    'MALICIOUS_TELEMETRY',
    'CRASH_REPORTING',
    'DIAGNOSTICS',
    'ATTRIBUTION',
    'ENCRYPTED_DNS',
    'ESSENTIAL_CONNECTIVITY',
    'ESSENTIAL_PUSH',
    'ESSENTIAL_UPDATE',
}
ESSENTIAL_CATEGORIES = {'ESSENTIAL_CONNECTIVITY', 'ESSENTIAL_PUSH', 'ESSENTIAL_UPDATE'}

PROTECTED_VENDOR_APEXES = {
    'google.com', 'googleapis.com', 'gstatic.com', 'android.com',
    'xiaomi.com', 'mi.com', 'miui.com', 'hyperos.com',
    'samsung.com', 'samsungcloudsolution.com', 'samsungknox.com', 'secb2b.com',
    'huawei.com', 'hicloud.com', 'dbankcloud.com', 'dbankcloud.cn',
    'oppo.com', 'oneplus.com', 'heytap.com', 'coloros.com', 'allawnos.com',
    'vivo.com', 'apple.com', 'icloud.com',
    'tuyaeu.com', 'tuyaus.com', 'tuyacn.com',
    'cloudflare.com', 'quad9.net', 'mullvad.net',
}

HIGH_RISK_GUARD_DOMAINS = {
    'hlth.io.mi.com',
    'firebaseinstallations.googleapis.com',
    'api.onesignal.com',
    'graph.facebook.com',
    'graph.instagram.com',
    'staticxx.facebook.com',
    'healthactivity-dre.things.hicloud.com',
    'healthdeviceagent-dre.things.hicloud.com',
}

DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
ID_RE = re.compile(r'^[a-z0-9][a-z0-9.-]{2,95}$')
IP_PREFIXES = ('0.0.0.0 ', '127.0.0.1 ', '::1 ', ':: ')


@dataclass(frozen=True)
class Rule:
    rule_id: str
    domain: str
    include_subdomains: bool
    category: str
    confidence: str
    breakage_risk: str
    essential: bool
    source_id: str
    source_url: str
    license_id: str
    observed_at: str

    def to_tsv(self) -> str:
        return '\t'.join([
            self.rule_id,
            self.domain,
            'true' if self.include_subdomains else 'false',
            self.category,
            self.confidence,
            self.breakage_risk,
            'true' if self.essential else 'false',
            self.source_id,
            self.source_url,
            self.license_id,
            self.observed_at,
        ])


def canonical_domain(raw: str) -> Optional[str]:
    dom = raw.strip().strip('.').lower()
    if not dom or len(dom) > 253 or not DOMAIN_RE.match(dom):
        return None
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', dom):
        return None
    return dom


def check_license(license_id: str) -> None:
    upper = license_id.upper()
    if any(tok in upper for tok in FORBIDDEN_LICENSE_TOKENS):
        raise ValueError(f'Forbidden license: {license_id}')
    if license_id not in ALLOWED_LICENSES:
        raise ValueError(f'License outside approved corridor: {license_id}')


def load_tsv_rules(path: Path) -> List[Rule]:
    rules: List[Rule] = []
    for line_no, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        fields = line.split('\t')
        if len(fields) != 11:
            raise ValueError(f'{path}:{line_no}: expected 11 columns, got {len(fields)}')
        rid, dom, sub, cat, conf, risk, ess, sid, url, lic, obs = fields
        if not ID_RE.match(rid):
            raise ValueError(f'{path}:{line_no}: invalid rule id {rid!r}')
        cdom = canonical_domain(dom)
        if not cdom:
            raise ValueError(f'{path}:{line_no}: invalid domain {dom!r}')
        if cat not in VALID_CATEGORIES:
            raise ValueError(f'{path}:{line_no}: invalid category {cat!r}')
        check_license(lic)
        rules.append(Rule(
            rule_id=rid,
            domain=cdom,
            include_subdomains=(sub == 'true'),
            category=cat,
            confidence=conf,
            breakage_risk=risk,
            essential=(ess == 'true'),
            source_id=sid,
            source_url=url,
            license_id=lic,
            observed_at=obs,
        ))
    return rules


def parse_upstream_feed(path: Path, source_id: str, license_id: str, category: str, source_url: str, observed_at: str) -> List[Rule]:
    check_license(license_id)
    if category not in VALID_CATEGORIES or category in ESSENTIAL_CATEGORIES:
        raise ValueError(f'Invalid block feed category: {category}')
    out: List[Rule] = []
    for raw in path.read_text(encoding='utf-8', errors='strict').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line or line.startswith('!') or line.startswith('['):
            continue
        for prefix in IP_PREFIXES:
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
                break
        include_sub = False
        if line.startswith('||') and line.endswith('^'):
            line = line[2:-1]
            include_sub = True
        elif line.startswith('*.'):
            line = line[2:]
            include_sub = True
        cdom = canonical_domain(line)
        if not cdom or cdom in PROTECTED_VENDOR_APEXES or cdom in HIGH_RISK_GUARD_DOMAINS:
            continue
        digest = hashlib.sha256(f'{source_id}:{cdom}'.encode('utf-8')).hexdigest()[:10]
        safe_src = re.sub(r'[^a-z0-9.-]', '-', source_id.lower())[:24].strip('.-') or 'feed'
        rid = f'{safe_src}-{digest}'
        out.append(Rule(
            rule_id=rid,
            domain=cdom,
            include_subdomains=include_sub,
            category=category,
            confidence='HIGH',
            breakage_risk='LOW',
            essential=False,
            source_id=source_id,
            source_url=source_url,
            license_id=license_id,
            observed_at=observed_at,
        ))
    return out


class SuffixTrie:
    """Reverse-label suffix trie for fast ancestor wildcard matching and child collapse."""

    def __init__(self) -> None:
        self.root: Dict[str, dict] = {}

    def insert_wildcard(self, domain: str, rule: Rule) -> None:
        node = self.root
        for label in reversed(domain.split('.')):
            node = node.setdefault(label, {})
        node['__rule__'] = rule

    def covering_parent(self, domain: str) -> Optional[Rule]:
        node = self.root
        labels = list(reversed(domain.split('.')))
        best: Optional[Rule] = None
        for idx, label in enumerate(labels):
            node = node.get(label)
            if node is None:
                break
            rule = node.get('__rule__')
            if rule is not None and idx < len(labels) - 1:
                best = rule
        return best


def merge_and_collapse(base_rules: Iterable[Rule], upstream_rules: Iterable[Rule], max_rules: int = 6000) -> List[Rule]:
    if not (1 <= max_rules <= MAX_PARSER_RULES):
        raise ValueError(f'max_rules must be within 1..{MAX_PARSER_RULES}')
    by_domain: Dict[str, Rule] = {}
    for r in base_rules:
        by_domain.setdefault(r.domain, r)

    essential_trie = SuffixTrie()
    block_trie = SuffixTrie()
    for r in by_domain.values():
        if r.essential and r.include_subdomains:
            essential_trie.insert_wildcard(r.domain, r)
        elif not r.essential and r.include_subdomains:
            block_trie.insert_wildcard(r.domain, r)

    essential_exact = {r.domain for r in by_domain.values() if r.essential}

    for r in upstream_rules:
        if r.domain in by_domain or r.domain in essential_exact or r.domain in PROTECTED_VENDOR_APEXES:
            continue
        if essential_trie.covering_parent(r.domain) is not None:
            continue
        parent = block_trie.covering_parent(r.domain)
        if parent is not None and parent.breakage_risk == 'LOW' and parent.category != 'ENCRYPTED_DNS':
            continue
        by_domain[r.domain] = r
        if r.include_subdomains and r.breakage_risk == 'LOW':
            block_trie.insert_wildcard(r.domain, r)

    ordered = sorted(by_domain.values(), key=lambda x: (0 if x.essential else 1, x.domain, x.rule_id))
    if len(ordered) > max_rules:
        raise ValueError(f'Collapsed rule count {len(ordered)} exceeds configured limit {max_rules}')
    return ordered


def run_self_test() -> None:
    today = str(date(2026, 11, 23))
    base = [
        Rule('ess-fcm-mtalk', 'mtalk.google.com', False, 'ESSENTIAL_PUSH', 'HIGH', 'HIGH', True, 'ref', 'https://firebase.google.com', 'REFERENCE', today),
        Rule('blk-ads-parent', 'tracker.example', True, 'ADS', 'HIGH', 'LOW', False, 'ref', 'https://example.org', 'MIT', today),
    ]
    upstream = [
        Rule('up-child', 'sub.tracker.example', False, 'ADS', 'HIGH', 'LOW', False, 'up', 'https://example.org', 'GPL-3.0', today),
        Rule('up-apex', 'google.com', True, 'ADS', 'HIGH', 'LOW', False, 'up', 'https://example.org', 'MIT', today),
        Rule('up-ess', 'mtalk.google.com', False, 'ADS', 'HIGH', 'LOW', False, 'up', 'https://example.org', 'MIT', today),
        Rule('up-keep', 'beacon.bad.example', False, 'MALICIOUS_TELEMETRY', 'HIGH', 'LOW', False, 'up', 'https://example.org', 'MIT', today),
    ]
    merged = merge_and_collapse(base, upstream, max_rules=6000)
    domains = {r.domain for r in merged}
    assert domains == {'mtalk.google.com', 'tracker.example', 'beacon.bad.example'}, f'Unexpected collapse result: {domains}'


def main() -> None:
    parser = argparse.ArgumentParser(description='GeDefense Mobile Stage-2 Privacy Feed Compiler')
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--base', type=Path)
    parser.add_argument('--upstream', action='append', default=[], help='source_id|license_id|category|source_url|file_path')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--max-rules', type=int, default=6000)
    args = parser.parse_args()
    if args.self_test:
        run_self_test()
        print('PRIVACY_FEED_COMPILER_SELF_TEST_PASS')
        return
    if not args.base or not args.out:
        parser.error('--base and --out are required unless --self-test is set')
    base = load_tsv_rules(args.base)
    today = str(date.today())
    upstream_rules: List[Rule] = []
    for spec in args.upstream:
        parts = spec.split('|', 4)
        if len(parts) != 5:
            parser.error(f'Invalid --upstream spec (expected 5 |-separated fields): {spec}')
        sid, lic, cat, url, fpath = parts
        upstream_rules.extend(parse_upstream_feed(Path(fpath), sid, lic, cat, url, today))
    collapsed = merge_and_collapse(base, upstream_rules, max_rules=args.max_rules)
    header = [
        '# GeDefense Privacy Intelligence Compiled Snapshot',
        '# id\tdomain\tincludeSubdomains\tcategory\tconfidence\tbreakageRisk\tessential\tsourceId\tsourceUrl\tlicenseId\tobservedAt',
    ]
    args.out.write_text('\n'.join(header + [r.to_tsv() for r in collapsed]) + '\n', encoding='utf-8')
    print(f'COMPILED rules={len(collapsed)} upstream_candidates={len(upstream_rules)}')


if __name__ == '__main__':
    main()

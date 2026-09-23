#!/usr/bin/env python3
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
RES = ROOT / "app" / "src" / "main" / "res"
FILES = {
    "en": RES / "values" / "strings.xml",
    "de": RES / "values-de" / "strings.xml",
    "ru": RES / "values-ru" / "strings.xml",
    "zh-CN": RES / "values-zh-rCN" / "strings.xml",
}
PLACEHOLDER = re.compile(r"%(?:\d+\$)?[,.(\-+ 0#]*[a-zA-Z]")
VALID_QUANTITIES = {"zero", "one", "two", "few", "many", "other"}


def text_of(node: ET.Element) -> str:
    return "".join(node.itertext()).strip()


def load(path: Path):
    root = ET.parse(path).getroot()
    strings = {}
    plurals = {}

    for node in root.findall("string"):
        name = node.attrib.get("name")
        if not name:
            raise SystemExit(f"missing string name in {path}")
        text = text_of(node)
        if not text:
            raise SystemExit(f"empty translation: {path}:{name}")
        if name in strings:
            raise SystemExit(f"duplicate translation key: {path}:{name}")
        strings[name] = text

    for node in root.findall("plurals"):
        name = node.attrib.get("name")
        if not name:
            raise SystemExit(f"missing plurals name in {path}")
        if name in plurals:
            raise SystemExit(f"duplicate plurals key: {path}:{name}")
        items = {}
        for item in node.findall("item"):
            quantity = item.attrib.get("quantity")
            if quantity not in VALID_QUANTITIES:
                raise SystemExit(f"invalid plural quantity: {path}:{name}:{quantity}")
            text = text_of(item)
            if not text:
                raise SystemExit(f"empty plural translation: {path}:{name}:{quantity}")
            if quantity in items:
                raise SystemExit(f"duplicate plural quantity: {path}:{name}:{quantity}")
            items[quantity] = text
        if "other" not in items:
            raise SystemExit(f"plural resource lacks required 'other': {path}:{name}")
        plurals[name] = items

    overlap = set(strings) & set(plurals)
    if overlap:
        raise SystemExit(f"resource names reused across string/plurals in {path}: {sorted(overlap)}")
    return strings, plurals


catalogs = {lang: load(path) for lang, path in FILES.items()}
base_strings, base_plurals = catalogs["en"]
base_string_keys = set(base_strings)
base_plural_keys = set(base_plurals)

for lang, (strings, plurals) in catalogs.items():
    string_keys = set(strings)
    plural_keys = set(plurals)
    if string_keys != base_string_keys:
        print(
            f"string key mismatch in {lang}: missing={sorted(base_string_keys-string_keys)} "
            f"extra={sorted(string_keys-base_string_keys)}",
            file=sys.stderr,
        )
        sys.exit(1)
    if plural_keys != base_plural_keys:
        print(
            f"plural key mismatch in {lang}: missing={sorted(base_plural_keys-plural_keys)} "
            f"extra={sorted(plural_keys-base_plural_keys)}",
            file=sys.stderr,
        )
        sys.exit(1)

    for key in sorted(base_string_keys):
        expected = sorted(PLACEHOLDER.findall(base_strings[key]))
        actual = sorted(PLACEHOLDER.findall(strings[key]))
        if expected != actual:
            print(f"placeholder mismatch {lang}:{key}: {expected} != {actual}", file=sys.stderr)
            sys.exit(1)

    for key in sorted(base_plural_keys):
        expected = sorted(PLACEHOLDER.findall(base_plurals[key]["other"]))
        for quantity, text in sorted(plurals[key].items()):
            actual = sorted(PLACEHOLDER.findall(text))
            if expected != actual:
                print(
                    f"plural placeholder mismatch {lang}:{key}:{quantity}: {expected} != {actual}",
                    file=sys.stderr,
                )
                sys.exit(1)

referenced_strings = set()
referenced_plurals = set()
for source in (ROOT / "app" / "src" / "main" / "java").rglob("*.kt"):
    content = source.read_text(encoding="utf-8")
    referenced_strings.update(re.findall(r"R\.string\.([A-Za-z0-9_]+)", content))
    referenced_plurals.update(re.findall(r"R\.plurals\.([A-Za-z0-9_]+)", content))

missing_strings = referenced_strings - base_string_keys
missing_plurals = referenced_plurals - base_plural_keys
if missing_strings:
    print(f"missing string resources referenced by Kotlin: {sorted(missing_strings)}", file=sys.stderr)
    sys.exit(1)
if missing_plurals:
    print(f"missing plural resources referenced by Kotlin: {sorted(missing_plurals)}", file=sys.stderr)
    sys.exit(1)

key_count = len(base_string_keys) + len(base_plural_keys)
referenced_count = len(referenced_strings) + len(referenced_plurals)
print(
    f"I18N_PASS languages={len(catalogs)} keys={key_count} referenced={referenced_count} "
    f"plurals={len(base_plural_keys)}"
)

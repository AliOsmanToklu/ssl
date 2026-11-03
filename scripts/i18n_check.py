"""Check the translation catalogs against the code.

Every message id used in the code (``T``, ``N_``, ``translate``, ``_``) and in the
templates (``_``, ``_m``) needs an entry in each ``src/kalkan/locale/<lang>.json`` with
the same ``{placeholders}`` and HTML tags. The test suite runs the same check.

    python scripts/i18n_check.py              # report problems, exit 1 if any
    python scripts/i18n_check.py --missing en # print missing ids as a JSON skeleton
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import string
import sys
from collections import defaultdict
from pathlib import Path

import jinja2
import jinja2.ext

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "kalkan"
LOCALE_DIR = PACKAGE / "locale"
PYTHON_CALLS = {"T", "N_", "translate", "_"}
TEMPLATE_CALLS = ("_", "_m")
_TAG = re.compile(r"</?[a-z]+>")

Messages = dict[str, set[str]]  # message id -> where it is used


def python_messages() -> Messages:
    found: Messages = defaultdict(set)
    for path in sorted(PACKAGE.rglob("*.py")):
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else None
            )
            first = node.args[0]
            if (
                name in PYTHON_CALLS
                and isinstance(first, ast.Constant)
                and isinstance(first.value, str)
            ):
                found[first.value].add(f"{path.relative_to(ROOT)}:{node.lineno}")
    return found


def template_messages() -> Messages:
    found: Messages = defaultdict(set)
    env = jinja2.Environment(autoescape=True)
    for path in sorted(PACKAGE.rglob("templates/*.html")):
        tree = env.parse(path.read_text("utf-8"))
        for lineno, _func, message in jinja2.ext.extract_from_ast(
            tree, gettext_functions=TEMPLATE_CALLS
        ):
            if isinstance(message, tuple):  # _("... {n}", n=...): the id comes first
                message = message[0] if message else None
            if isinstance(message, str):
                found[message].add(f"{path.relative_to(ROOT)}:{lineno}")
    return found


def all_messages() -> Messages:
    merged: Messages = defaultdict(set)
    for source in (python_messages(), template_messages()):
        for msgid, places in source.items():
            merged[msgid] |= places
    return merged


def placeholders(text: str) -> set[str]:
    return {field for _, field, _, _ in string.Formatter().parse(text) if field}


def tags(text: str) -> list[str]:
    return sorted(_TAG.findall(text))


def load_catalog(lang: str) -> dict[str, str | dict[str, str]]:
    data: dict[str, str | dict[str, str]] = json.loads(
        (LOCALE_DIR / f"{lang}.json").read_text("utf-8")
    )
    return data


def problems(lang: str, messages: Messages | None = None) -> list[str]:
    """Human-readable problems with one catalog (empty when it is complete)."""
    messages = all_messages() if messages is None else messages
    catalog = load_catalog(lang)
    found: list[str] = []
    for msgid in sorted(messages):
        entry = catalog.get(msgid)
        where = sorted(messages[msgid])[0]
        if entry is None:
            found.append(f"missing ({where}): {msgid!r}")
            continue
        variants = entry if isinstance(entry, dict) else {"other": entry}
        if not variants.get("other"):
            found.append(f"empty ({where}): {msgid!r}")
            continue
        expected = placeholders(msgid)
        for form, text in variants.items():
            got = placeholders(text)
            # "one" may spell the number out ("1 new issue" -> "a new issue")
            ok = got <= expected if form == "one" else got == expected
            if not ok:
                found.append(f"placeholders {sorted(got)} != {sorted(expected)}: {msgid!r}")
            if tags(text) != tags(msgid):
                found.append(f"HTML tags differ: {msgid!r}")
    for msgid in sorted(set(catalog) - set(messages)):
        found.append(f"unused: {msgid!r}")
    return found


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--missing", metavar="LANG", help="print missing ids as JSON")
    args = parser.parse_args()
    messages = all_messages()
    if args.missing:
        catalog = load_catalog(args.missing)
        missing = {m: "" for m in sorted(messages) if m not in catalog}
        json.dump(missing, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0
    status = 0
    for path in sorted(LOCALE_DIR.glob("*.json")):
        issues = problems(path.stem, messages)
        print(f"{path.stem}: {len(messages)} messages, {len(issues)} problem(s)")
        for issue in issues:
            print("  " + issue)
        status = status or int(bool(issues))
    return status


if __name__ == "__main__":
    sys.exit(main())

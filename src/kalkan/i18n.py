"""Translations: Turkish is the source language, other languages come from catalogs.

Message ids are the Turkish text itself (the product's primary language), with named
``{placeholders}``. ``kalkan/locale/<lang>.json`` maps each id to its translation; an
entry may be ``{"one": ..., "other": ...}`` for count-dependent wording, chosen by the
``n`` parameter.

Two ways to translate:

* :func:`translate` renders a message in one language right away (pages, e-mails).
* :func:`T` renders it in *every* language and returns a :class:`Text`. Scan findings
  use this: the stored report then reads correctly in any language later on.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import cache
from importlib import resources
from typing import Any

LANGUAGES: dict[str, str] = {"tr": "Türkçe", "en": "English"}
DEFAULT_LANGUAGE = "tr"


@cache
def catalog(lang: str) -> Mapping[str, str | dict[str, str]]:
    if lang == DEFAULT_LANGUAGE or lang not in LANGUAGES:
        return {}
    text = resources.files("kalkan").joinpath(f"locale/{lang}.json").read_text("utf-8")
    data: dict[str, str | dict[str, str]] = json.loads(text)
    return data


def normalize_language(value: str | None) -> str:
    code = (value or "").strip().lower().replace("_", "-").split("-")[0]
    return code if code in LANGUAGES else DEFAULT_LANGUAGE


def best_language(accept_language: str | None) -> str:
    """Pick a supported language from an ``Accept-Language`` header."""
    choices: list[tuple[float, int, str]] = []
    for index, part in enumerate((accept_language or "").split(",")):
        tag, _, q = part.strip().partition(";q=")
        try:
            weight = float(q) if q else 1.0
        except ValueError:
            weight = 0.0
        code = tag.strip().lower().split("-")[0]
        if code in LANGUAGES and weight > 0:
            choices.append((-weight, index, code))
    return min(choices)[2] if choices else DEFAULT_LANGUAGE


def _template(msgid: str, lang: str, params: Mapping[str, Any]) -> str:
    entry = catalog(lang).get(msgid, msgid)
    if isinstance(entry, dict):
        entry = entry.get("one" if params.get("n") == 1 else "other") or msgid
    return entry


def _localize(value: Any, lang: str) -> Any:
    return value.get(lang) if isinstance(value, Text) else value


def translate(msgid: str, lang: str = DEFAULT_LANGUAGE, /, **params: Any) -> str:
    """``msgid`` in ``lang``, with ``params`` filled in (they may be :class:`Text`)."""
    lang = normalize_language(lang)
    template = _template(msgid, lang, params)
    if not params:
        return template
    return template.format(**{key: _localize(value, lang) for key, value in params.items()})


class Text:
    """A piece of user-facing text in every supported language."""

    __slots__ = ("values",)

    def __init__(self, values: Mapping[str, str]) -> None:
        if DEFAULT_LANGUAGE not in values:
            raise ValueError("a Text needs at least the default language")
        self.values: dict[str, str] = dict(values)

    @classmethod
    def plain(cls, value: str) -> Text:
        """Untranslatable text (a URL, a version): the same in every language."""
        return cls({lang: value for lang in LANGUAGES})

    def get(self, lang: str) -> str:
        return self.values.get(lang) or self.values[DEFAULT_LANGUAGE]

    def __str__(self) -> str:
        return self.values[DEFAULT_LANGUAGE]

    def __repr__(self) -> str:
        return f"Text({self.values!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Text):
            return self.values == other.values
        if isinstance(other, str):
            return str(self) == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(str(self))

    def __bool__(self) -> bool:
        return bool(str(self))

    def __contains__(self, item: str) -> bool:
        return any(item in value for value in self.values.values())

    def __add__(self, other: Text | str) -> Text:
        return Text({lang: self.get(lang) + _as_text(other).get(lang) for lang in LANGUAGES})

    def __radd__(self, other: str) -> Text:
        return Text({lang: other + self.get(lang) for lang in LANGUAGES})

    def to_json(self) -> dict[str, str]:
        return dict(self.values)


def _as_text(value: Text | str) -> Text:
    return value if isinstance(value, Text) else Text.plain(value)


def T(msgid: str, /, **params: Any) -> Text:
    """``msgid`` rendered in every supported language."""
    return Text({lang: translate(msgid, lang, **params) for lang in LANGUAGES})


def N_(msgid: str) -> str:
    """Mark a message for translation without translating it now (labels, constants).
    The string is rendered later with :func:`translate` or :func:`localize`."""
    return msgid


LocalizedValue = Text | str


def to_json(value: LocalizedValue) -> str | dict[str, str]:
    return value.to_json() if isinstance(value, Text) else value


def from_json(value: Any) -> LocalizedValue:
    if isinstance(value, dict) and isinstance(value.get(DEFAULT_LANGUAGE), str):
        return Text({str(k): str(v) for k, v in value.items()})
    return str(value)


def localize(value: Any, lang: str) -> str:
    """Render a stored value in ``lang``. Plain strings (reports saved before translations
    existed) are looked up in the catalog, which covers every static message."""
    if isinstance(value, Text):
        return value.get(lang)
    if isinstance(value, dict) and DEFAULT_LANGUAGE in value:
        return str(value.get(lang) or value[DEFAULT_LANGUAGE])
    text = str(value)
    if lang == DEFAULT_LANGUAGE:
        return text
    entry = catalog(normalize_language(lang)).get(text)
    return entry if isinstance(entry, str) else text

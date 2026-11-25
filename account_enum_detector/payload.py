"""Account generation and request-body construction."""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

from .safety import looks_like_email


@dataclass
class BodyConfig:
    content_type: str = "application/json"
    template: str | None = None
    account_placeholder: str = "{{account}}"
    password: str | None = None
    password_placeholder: str = "{{password}}"
    account_field: str = "username"
    password_field: str = "password"
    extra_fields: dict[str, str] = field(default_factory=dict)
    mode: str = "generic"

    def uses_password(self) -> bool:
        if self.password_placeholder in (self.template or ""):
            return True
        return self.mode == "login" and self.template is None


def default_nonexistent_pattern(known_accounts: list[str]) -> str:
    first = known_accounts[0] if known_accounts else ""
    if looks_like_email(first):
        domain = first.partition("@")[2]
        return "ae-enum-{{uuid}}@" + domain
    return "ae_enum_{{uuid}}"


def render_account_pattern(pattern: str, index: int) -> str:
    value = pattern
    # Documented pattern syntax is {{uuid}}. Also accept {uuid} for convenience.
    replacements = {
        "{{uuid}}": uuid.uuid4().hex,
        "{{shortuuid}}": uuid.uuid4().hex[:12],
        "{{timestamp}}": str(int(time.time())),
        "{{index}}": str(index),
        "{uuid}": uuid.uuid4().hex,
        "{shortuuid}": uuid.uuid4().hex[:12],
        "{timestamp}": str(int(time.time())),
        "{index}": str(index),
    }
    for token, replacement in replacements.items():
        value = value.replace(token, replacement)
    return value


def _template_values(account: str, password: str | None, index: int) -> dict[str, str]:
    return {
        "account": account,
        "password": password or "",
        "uuid": uuid.uuid4().hex,
        "shortuuid": uuid.uuid4().hex[:12],
        "timestamp": str(int(time.time())),
        "index": str(index),
    }


def _replace_tokens(text: str, values: dict[str, str], url_quote: bool = False) -> str:
    for key, val in values.items():
        replacement = quote(val, safe="") if url_quote and key in {"account", "password"} else val
        text = text.replace("{{" + key + "}}", replacement)
    return text


def _render_obj(obj: Any, values: dict[str, str]) -> Any:
    if isinstance(obj, str):
        return _replace_tokens(obj, values)
    if isinstance(obj, list):
        return [_render_obj(v, values) for v in obj]
    if isinstance(obj, dict):
        return {k: _render_obj(v, values) for k, v in obj.items()}
    return obj


def build_body(account: str, index: int, config: BodyConfig) -> bytes:
    values = _template_values(account, config.password, index)
    content_type = config.content_type.lower()

    if config.template is not None:
        template = config.template
        wants_form = "x-www-form-urlencoded" in content_type
        wants_json = "json" in content_type
        looks_json = wants_json or template.lstrip()[:1] in {"{", "["}

        parsed: Any | None = None
        if looks_json:
            try:
                parsed = json.loads(template)
            except json.JSONDecodeError:
                parsed = None

        if parsed is not None:
            rendered_obj = _render_obj(parsed, values)
            if wants_form:
                if not isinstance(rendered_obj, dict):
                    raise ValueError("JSON form template must be an object whose keys are form fields")
                return urlencode(rendered_obj, doseq=True).encode("utf-8")
            return json.dumps(rendered_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

        if wants_form:
            return _replace_tokens(template, values, url_quote=True).encode("utf-8")
        return _replace_tokens(template, values).encode("utf-8")

    fields: dict[str, Any] = {config.account_field: account}
    if config.mode == "login":
        if not config.password:
            raise ValueError("login mode requires --password or the referenced password environment variable")
        fields[config.password_field] = config.password
    fields.update(config.extra_fields)

    if "json" in content_type:
        return json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return urlencode(fields, doseq=True).encode("utf-8")

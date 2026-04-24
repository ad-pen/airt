from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from airt.models import (
    AttackClass,
    ConfigError,
    Payload,
    Severity,
    SuccessCriteria,
    Target,
)

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_VALID_ATTACK_CLASSES = {e.value for e in AttackClass}
_VALID_SEVERITIES = {e.value for e in Severity}
_VALID_SUCCESS_FIELDS = set(SuccessCriteria.model_fields.keys())


def load_target(path: str | Path) -> Target:
    """Load and validate a target config from a YAML file."""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
        return Target.model_validate(data)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}")
    except ValidationError as e:
        raise ConfigError(f"Invalid target config in {path}: {e}")


def load_payload(path: str | Path) -> Payload:
    """Load and validate a payload config from a YAML file."""
    path = Path(path)
    try:
        data = yaml.safe_load(path.read_text())
        return Payload.model_validate(data)
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}")
    except ValidationError as e:
        raise ConfigError(f"Invalid payload config in {path}: {e}")


def _severity_value(sev: str | Severity) -> int:
    """Return numeric severity level for comparison."""
    s = sev.value if isinstance(sev, Severity) else sev.lower()
    return _SEVERITY_ORDER[s]


def _matches_filters(
    payload: Payload,
    *,
    attack_class: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    severity: str | None = None,
    min_severity: str | None = None,
) -> bool:
    """Return True if the payload matches all provided filters."""
    if attack_class is not None:
        if payload.attack_class.value != attack_class:
            return False

    if owasp is not None:
        if payload.owasp is None or owasp.lower() not in payload.owasp.lower():
            return False

    if tag is not None:
        if not any(tag.lower() in t.lower() for t in payload.tags):
            return False

    if severity is not None:
        if payload.severity_if_success.value != severity.lower():
            return False

    if min_severity is not None:
        threshold = _SEVERITY_ORDER.get(min_severity.lower())
        if threshold is None:
            raise ConfigError(
                f"Unknown severity level: {min_severity!r}. "
                f"Valid levels: {', '.join(_SEVERITY_ORDER)}"
            )
        if _severity_value(payload.severity_if_success) < threshold:
            return False

    return True


def load_payloads_dir(
    directory: str | Path,
    *,
    attack_class: str | None = None,
    owasp: str | None = None,
    tag: str | None = None,
    severity: str | None = None,
    min_severity: str | None = None,
) -> list[Payload]:
    """Load payloads from directory with optional filtering.

    Filters:
    - attack_class: only payloads matching this attack class
    - owasp: only payloads tagged with this OWASP category
    - tag: only payloads containing this tag
    - severity: only payloads with this exact severity
    - min_severity: only payloads at or above this severity level
    """
    dir_path = Path(directory)
    payloads: list[Payload] = []
    seen: set[Path] = set()

    for pattern in ("*.yaml", "*.yml"):
        for p in sorted(dir_path.rglob(pattern)):
            resolved = p.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            payload = load_payload(p)
            if _matches_filters(
                payload,
                attack_class=attack_class,
                owasp=owasp,
                tag=tag,
                severity=severity,
                min_severity=min_severity,
            ):
                payloads.append(payload)

    return payloads


def validate_target(path: str | Path) -> list[str]:
    """Validate a target config file. Returns list of issues (empty = valid)."""
    path = Path(path)
    issues: list[str] = []

    if not path.exists():
        issues.append(f"File does not exist: {path}")
        return issues

    try:
        raw = path.read_text()
    except OSError as e:
        issues.append(f"Cannot read file: {e}")
        return issues

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        issues.append(f"Invalid YAML: {e}")
        return issues

    if not isinstance(data, dict):
        issues.append("Top-level value must be a mapping")
        return issues

    # Required fields
    if "name" not in data:
        issues.append("Missing required field: name")
    if "request" not in data:
        issues.append("Missing required field: request")
    else:
        req = data["request"]
        if not isinstance(req, dict):
            issues.append("'request' must be a mapping")
        else:
            if "url" not in req:
                issues.append("Missing required field: request.url")
            method = req.get("method", "POST")
            if method not in ("POST", "GET", "PUT"):
                issues.append(
                    f"Invalid request.method: {method!r}. Must be POST, GET, or PUT"
                )
            hf = req.get("history_format", "openai")
            if hf not in ("openai", "anthropic", "plain-latest"):
                issues.append(
                    f"Invalid request.history_format: {hf!r}. "
                    "Must be openai, anthropic, or plain-latest"
                )

    # Try full model validation to catch extra fields, type errors, etc.
    try:
        Target.model_validate(data)
    except ValidationError as e:
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            issues.append(f"Validation error at {loc}: {err['msg']}")

    return issues


def validate_payload(path: str | Path) -> list[str]:
    """Validate a payload config file. Returns list of issues (empty = valid)."""
    path = Path(path)
    issues: list[str] = []

    if not path.exists():
        issues.append(f"File does not exist: {path}")
        return issues

    try:
        raw = path.read_text()
    except OSError as e:
        issues.append(f"Cannot read file: {e}")
        return issues

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        issues.append(f"Invalid YAML: {e}")
        return issues

    if not isinstance(data, dict):
        issues.append("Top-level value must be a mapping")
        return issues

    # Required fields
    if "id" not in data:
        issues.append("Missing required field: id")
    if "attack_class" not in data:
        issues.append("Missing required field: attack_class")
    elif data["attack_class"] not in _VALID_ATTACK_CLASSES:
        issues.append(
            f"Invalid attack_class: {data['attack_class']!r}. "
            f"Valid values: {', '.join(sorted(_VALID_ATTACK_CLASSES))}"
        )
    if "title" not in data:
        issues.append("Missing required field: title")

    # Turns validation
    if "turns" not in data:
        issues.append("Missing required field: turns")
    else:
        turns = data["turns"]
        if not isinstance(turns, list):
            issues.append("'turns' must be a list")
        elif len(turns) == 0:
            issues.append("'turns' list must not be empty")

    # Severity validation
    sev = data.get("severity_if_success")
    if sev is not None and sev not in _VALID_SEVERITIES:
        issues.append(
            f"Invalid severity_if_success: {sev!r}. "
            f"Valid values: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    # Success criteria field validation
    for criteria_name in ("success", "partial"):
        criteria = data.get(criteria_name)
        if criteria is not None and isinstance(criteria, dict):
            unknown = set(criteria.keys()) - _VALID_SUCCESS_FIELDS
            if unknown:
                issues.append(
                    f"Unknown fields in {criteria_name}: {', '.join(sorted(unknown))}"
                )

    # Try full model validation to catch extra fields, type errors, etc.
    try:
        Payload.model_validate(data)
    except ValidationError as e:
        for err in e.errors():
            loc = ".".join(str(x) for x in err["loc"])
            issues.append(f"Validation error at {loc}: {err['msg']}")

    return issues

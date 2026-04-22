from __future__ import annotations

from pathlib import Path

import yaml

from airt.models import Payload, Target


def load_target(path: Path) -> Target:
    with path.open() as f:
        data = yaml.safe_load(f)
    return Target.model_validate(data)


def load_payload(path: Path) -> Payload:
    with path.open() as f:
        data = yaml.safe_load(f)
    return Payload.model_validate(data)


def load_payloads_dir(dir_path: Path) -> list[Payload]:
    payloads = []
    for p in sorted(dir_path.rglob("*.yaml")):
        payloads.append(load_payload(p))
    for p in sorted(dir_path.rglob("*.yml")):
        payloads.append(load_payload(p))
    return payloads

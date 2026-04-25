# Contributing to airt

Thanks for your interest in contributing to airt! This guide covers the basics.

## Dev setup

```bash
git clone https://github.com/ad-pen/airt.git
cd airt
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
```

Requires Python 3.11+.

## Running tests

```bash
python -m pytest -q
```

All tests must pass before submitting a PR. Tests run on Python 3.11, 3.12, and 3.13 in CI.

## Project structure

```
src/airt/
├── cli/            # Typer CLI commands (one file per command group)
├── adapters/       # HTTP, SMTP, URL embed, document injection adapters
├── models.py       # Pydantic models (Target, Payload, SessionResult, etc.)
├── engine.py       # Attack chain execution engine
├── detectors.py    # Rule-based response detectors (25 detectors)
├── loader.py       # YAML config loading and validation
├── storage.py      # SQLite session storage
├── transforms.py   # Payload encoding transforms
├── fuzzer.py       # Fuzzing mutation strategies
├── recon.py        # Reconnaissance probes
├── owasp.py        # OWASP LLM Top 10 mapping
├── presets.py      # Provider presets for scan command
├── demo_bot.py     # AcmeBot — deliberately vulnerable chatbot
└── report.py       # Markdown/PDF report generation
payloads/           # YAML payload definitions (one per attack)
targets/            # Example target configs
tests/              # pytest test suite
```

## Adding a payload

Payloads live in `payloads/<attack-class>/`. Each payload is a YAML file:

```yaml
id: attack-class.descriptive-name
attack_class: prompt-injection   # must be a valid AttackClass enum value
title: Short human-readable title
severity_if_success: high        # info | low | medium | high | critical
turns:
  - user: "The prompt text to send"
success:
  contains_any: ["expected", "strings"]
recommendation: |
  How to fix this vulnerability.
```

Validate your payload before submitting:

```bash
airt validate --dir payloads/
```

### Payload guidelines

- One vulnerability per payload — keep them focused
- Include `success` criteria so detection works automatically
- Include a `recommendation` field with actionable remediation advice
- Use `canary` strings when testing for data leakage
- Set `severity_if_success` based on real-world impact

## Adding a detector

Detectors live in `src/airt/detectors.py`. Each detector is a function that takes a response string and returns a `DetectorFlag` or `None`. Register it in the `DETECTORS` list.

## Adding a fuzzer strategy

Fuzzer strategies live in `src/airt/fuzzer.py`. Use the `@fuzzer("strategy-name")` decorator:

```python
@fuzzer("my-strategy")
def _my_strategy(text: str) -> str:
    # Mutate text to bypass filters
    return mutated_text
```

Use `_rng(text)` for a seeded RNG if your strategy is probabilistic — this keeps tests deterministic.

## Adding a transform

Transforms live in `src/airt/transforms.py`. Use the `@transform("name")` decorator.

## Code style

- Type hints on all public functions
- No comments unless the *why* is non-obvious
- Keep imports sorted: stdlib, third-party, local
- Use `from __future__ import annotations` at the top of every module

## Pull requests

1. Fork the repo and create a feature branch
2. Make your changes
3. Run `python -m pytest -q` — all tests must pass
4. Submit a PR against `main`

Keep PRs focused: one feature or fix per PR. Include tests for new functionality.

## Reporting issues

Open an issue on GitHub. For security vulnerabilities, please email directly rather than opening a public issue.

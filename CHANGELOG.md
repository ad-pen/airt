# Changelog

## 0.3.1 — 2026-04-25

### Added

- **Concurrent scanning** — `--concurrency` / `-c` flag on `scan`, `run-suite`,
  and `demo` commands. Run multiple payloads in parallel with semaphore-based
  throttling (default: 1, max: 50). Example: `airt scan URL -c 10`.
- **`airt judge` command** — LLM-as-judge for automated triage of ambiguous
  results. Evaluates FLAGS_PRESENT and NO_SIGNAL sessions with a judge LLM to
  classify them as success/partial/failure/unclear with confidence scores.
  Supports `--status` filter, `--min-confidence` threshold, and `--goal` override.

### Changed

- Total command count: 24 → 25.
- Test count: 453 → 459.

## 0.3.0 — 2026-04-25

### Added

- **CI workflow** — `.github/workflows/ci.yml` with Python 3.11/3.12/3.13
  matrix, pytest, payload validation, and CLI smoke test.
- **LICENSE file** — Apache-2.0 full text with copyright notice.
- **CONTRIBUTING.md** — contributor guide covering dev setup, tests, payload
  format, detectors, fuzzers, transforms, and PR process.
- **Integration tests** — 13 end-to-end tests running full attack chains
  against AcmeBot through both the engine API and the CLI (`scan`, `demo`,
  `report`). Tests cover system prompt extraction, canary detection, refusal
  behavior, full suite execution, storage round-trip, and `--fail-on-success`.
- **`--owasp` filter** — wired into `list-payloads`, `run-suite`, and `scan`
  commands. Filter payloads by OWASP LLM Top 10 category (e.g. `--owasp LLM01`).
- **`airt diff` command** — compare two scan databases to show regressions
  (new successes), fixes (previously succeeding payloads now deflected),
  and added/removed payloads. For tracking security improvements between runs.
- **Shell completions docs** — documented `airt --install-completion` in README.

### Changed

- Total command count: 23 → 24.
- Test count: 418 → 453.

## 0.2.0 — 2026-04-25

### Added

- **`airt scan` command** — point-and-shoot scanning. Give it a URL, it
  auto-detects the API format and runs all payloads. No YAML config needed.
  Supports presets for OpenAI, Anthropic, Azure, Ollama, and generic endpoints.
- **Fuzzer module** — 7 mutation strategies (whitespace-inject, case-random,
  char-substitute, word-split, dupe-spaces, zero-width, homoglyph) for
  bypassing keyword filters. Available via `airt fuzz`.
- **Recon module** — 7 automated probes (baseline, system-prompt, identity,
  length, tool, encoding, boundary) for fingerprinting targets before attacks.
  Available via `airt recon`.
- **OWASP LLM Top 10 mapping** — `airt coverage` shows which attack classes
  map to which OWASP categories and how many payloads cover each.
- **Document injection** — `airt craft-doc` creates poisoned PDFs and DOCX
  files with 8 injection methods (white-on-white, font-size-zero, hidden text,
  comments, metadata, etc.).
- **Email delivery** — `airt email` sends crafted emails for testing AI email
  assistants (body, html-hidden, attachment, header methods).
- **Poisoned URL server** — `airt serve` hosts a page with embedded payloads
  for indirect injection testing against AI agents.
- **Dynamic attacks** — `airt dynamic` uses an attacker LLM to adaptively
  probe targets with multi-turn conversations.
- **Import commands** — `airt import-curl` and `airt import-har` generate
  target configs from captured traffic.
- **Discovery commands** — `list-payloads`, `list-detectors`, `transform`,
  `validate`, `coverage` for exploring and validating the payload library.
- **Demo mode** — `airt demo` runs all payloads against the built-in AcmeBot
  (a deliberately vulnerable chatbot) with no external dependencies.
- **PDF reports** — `airt report -a -o report.pdf` generates PDF output.
- **Suite filtering** — `--attack-class`, `--tag`, `--min-severity` flags on
  `run-suite` and `scan` to scope what gets tested.
- **Payload transforms** — `--transform` flag on `run` and `run-suite` to
  apply encoding transforms (base64, rot13, leetspeak, etc.) before sending.
- **CI mode** — `--fail-on-success` flag on `run`, `run-suite`, and `scan`
  for pipeline integration.
- **Progress bars** — Rich progress bars on `run-suite`, `scan`, and `demo`.
- **`python -m airt`** support.
- **`airt version`** command.

### Changed

- Total command count: 10 → 23.
- Payload count: 127 across 8 attack classes (7/10 OWASP LLM Top 10 covered).
- Test count: 418.

## 0.1.0 — 2026-04-24

Initial release.

- HTTP adapter with configurable body templates and response path extraction.
- Scripted multi-turn attack chains with conditional branching.
- 25 rule-based detectors (canary, PII, tool-call, exfil, role-flip, etc.).
- SQLite session storage.
- Markdown report export.
- AcmeBot demo target.
- 7 encoding transforms (base64, rot13, leetspeak, hex, reverse, morse,
  unicode-tags).
- Session management (list, show, promote, findings).

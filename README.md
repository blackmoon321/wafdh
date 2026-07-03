# wafdh (WAF Detect Hae)

Concurrent WAF detection CLI with one main coordinator, internal scan workers, and a Codex-based final classifier. It follows the wafw00f-style flow for evidence collection, then uses an LLM as the final WAF classifier.

## Supported Environment

| Area | Requirement / support | Notes |
| --- | --- | --- |
| Python | 3.13 or newer | `wafdh` package metadata requires Python 3.13+. Development currently targets Python 3.14. |
| Operating system | macOS x86_64/arm64, Windows amd64/arm64, Linux x86_64/aarch64 | The current `openai-codex` pinned runtime publishes wheels for these platforms. macOS is locally verified; Windows and Linux support is based on package wheel support. |
| Package install | `pipx` recommended | A plain virtual environment with `pip3 install -r requirements.txt` is also supported. |
| Codex auth | Local Codex CLI login with ChatGPT OAuth | Default LLM classification reuses the local Codex login cache. `wafdh` does not ask for an OpenAI API key. |
| Offline mode | Python-only deterministic scanning | Use `--llm-provider off` when Codex classification should be disabled. |

## Setup

Install Python 3.13 or newer and `pipx` first. If the `codex` command is not
already available, install the Codex CLI for your platform, then authenticate it:

```bash
codex login
codex login status
```

`codex login` uses the browser-based ChatGPT OAuth flow by default. For remote or
headless environments, use device-code login instead:

```bash
codex login --device-auth
```

Install with pipx:

```bash
pipx install git+https://github.com/blackmoon321/wafdh.git
```

The package requires Python 3.13 or newer. If pipx uses an older default Python,
pass a newer interpreter explicitly:

```bash
pipx install --python python3.14 git+https://github.com/blackmoon321/wafdh.git
```

For local development:

```bash
uv sync
```

For a plain Python environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
pip3 install -e .
```

By default, the scanner uses the Python `openai-codex` SDK as the final
classifier with Codex model `gpt-5.5`. The SDK controls the local Codex
app-server and uses the local Codex authentication state created by
`codex login`. Each classification starts with reasoning effort `high`, then
escalates the same Codex thread to `xhigh` only when the first verdict is
low/medium confidence or still names a generic/unknown WAF.

Use `--llm-provider off` only for offline deterministic testing.

Codex classification is required in the default `--llm-provider codex` mode. A
single Codex turn waits up to `--codex-turn-timeout` seconds, defaulting to
`600`, and each target gets up to `--codex-max-attempts` fresh Codex app-server
attempts, defaulting to `3`. If all attempts fail, the run stops without writing
that target as completed; rerun with `--resume` after Codex connectivity recovers
to classify the same unfinished target.

## Usage

```bash
uv run wafdh -u https://example.com
uv run wafdh -l targets.txt
uv run wafdh -u https://example.com -o report.csv
uv run wafdh -l targets.txt -o report.csv
uv run wafdh -l targets.txt --codex-turn-timeout 900 --codex-max-attempts 4
uv run wafdh --llm-provider off -u https://example.com -o report.csv
uv run wafdh -l targets.txt --resume data/wafdh-20260702T000000Z-targets.partial.jsonl -o report.csv
uv run wafdh list-rules
```

Bare hostnames expand to both `https://host` and `http://host`. Redirects are followed, but crawl/scrape stays disabled unless the final URL remains on the same host as the submitted target. When a scan starts, the CLI prints a `wafdh` ASCII banner with `by blackmoon`, then shows a progress bar that advances as each expanded target finishes. Detailed JSON reports are saved under `data/` by default, and each completed target is also appended to a `data/*.partial.jsonl` checkpoint while the scan is running. On successful completion the final detailed JSON is written and the checkpoint is removed; if the scan stops early, the checkpoint keeps the target reports completed so far. `-o/--output` writes the visible summary rows as CSV. The console prints the summary table plus saved paths. JSON reports include `waf_status` values: `detected`, `not_detected`, `unknown`, or `scan_failed`.

To recover a stopped run, rerun the same `-u` or `-l` input with the printed
checkpoint path:

```bash
wafdh -l targets.txt --resume data/wafdh-20260702T000000Z-targets.partial.jsonl -o report.csv
```

The resumed run skips targets already present in the checkpoint, appends newly
completed targets to that same checkpoint while it runs, then writes the final
JSON and optional CSV before removing the checkpoint.

## Architecture

`MainAgent` normalizes the target list, loads built-in rules, creates one optimized shared HTTP client, configures the selected LLM provider, and starts internal scan workers with AnyIO streams. These are process-local URL scanning workers, not Codex or LLM agent instances. Worker count is selected from the submitted target count before bare hostnames are expanded to both HTTP and HTTPS.

Default `--llm-provider codex` mode keeps HTTP workers and Codex classifiers in a
1:1 ratio because each successful target receives an LLM verdict:

| Submitted targets | Concurrent scan workers | Concurrent Codex classifications |
| --- | ---: | ---: |
| single target | 1 | 1 |
| 2 to 4 targets | target count | target count |
| 5 or more targets | 4 | 4 |

When `--llm-provider off` is used for deterministic-only scanning, worker count
can scale higher because no Codex classifications run:

| Submitted targets | Concurrent scan workers |
| --- | ---: |
| single target | 1 |
| list up to 10 | up to 4 |
| list up to 100 | up to 10 |
| list up to 1,000 | up to 25 |
| list up to 10,000 | up to 50 |
| list over 10,000 | capped at 64 |

The deterministic-only hard worker cap is 64 to avoid excessive local file
descriptor use, HTTP connection pressure, and target-side load.

Each scan worker:

1. Sends a baseline request.
2. Follows redirects through the HTTP client.
3. Crawls same-host pages only.
4. Scrapes links, query strings, and form field names.
5. Sends bounded GET-only WAF probe payloads.
6. Runs deterministic signature and generic response-difference detection.
7. Asks the selected LLM provider to classify the final WAF name from all collected evidence.

## Development Tooling

Runtime WAF classification uses Codex model `gpt-5.5` through the Python
`openai-codex` SDK. The default classifier runs `high` effort first and escalates
to `xhigh` only for uncertain, generic, or unknown WAF names. Classification
concurrency is capped at 4, and default HTTP worker concurrency is capped to the
same value so large target lists do not open dozens of Codex runs at once.
LazyCodex/oh-my-codex was used as development orchestration tooling for this
repository; it is not required to install or run `wafdh`.

## Safety Boundary

Run this only against systems you are authorized to assess. Probes are bounded, GET-only, and intended to trigger WAF signatures without mutating application state, but they can still create security logs and alerts.

## Attribution

This project follows the WAF fingerprinting flow popularized by WAFW00F:
baseline HTTP response analysis, WAF-oriented probe requests, signature matching,
and fallback heuristic classification. It is not a fork or vendored copy of
WAFW00F.

Reference: https://github.com/EnableSecurity/wafw00f

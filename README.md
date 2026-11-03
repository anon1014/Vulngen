# VulnGen demo

A laptop-scale demo of a tool that generates **intentionally vulnerable** code with verified ground
truth, then scores traditional scanners and an AI reviewer against it.

```
Generate (Gemini)  →  Verify (Docker sandbox)  →  Scan (Semgrep / Bandit / Cppcheck / Gemini)  →  Score
```

- **Generate:** Gemini writes a small program with one chosen vulnerability, a minimally patched twin,
  and a proof-of-concept trigger, returned as structured JSON.
- **Ground truth:** the lines the patch changes (computed with a diff, not taken from the model's word).
- **Verify:** the trigger must succeed on the vulnerable version and fail on the patched twin.
  - Python: the trigger prints `EXPLOITED`.
  - C: the program is built with AddressSanitizer, and the trigger must crash the vulnerable build only.
  - Cases that fail verification are kept for inspection but excluded from scoring.
- **Score:** detection rate, exact-CWE rate, false alarms on the patched twin, and other findings.

> ⚠️ Everything under `data/cases/` is deliberately vulnerable. Never deploy, publish, or reuse it.

## Requirements

- Python 3.11+
- Docker Desktop (or Docker Engine), running
- Cppcheck for the C scanner: `brew install cppcheck`, `sudo apt install cppcheck`, or `choco install cppcheck`
- A Gemini API key from Google AI Studio (optional: the built-in samples work without one)

On Windows, Semgrep works best under WSL. Run the whole demo there if you can.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # then add GEMINI_API_KEY
docker build -t vulngen-sandbox:latest sandbox/   # or use the button in the sidebar
streamlit run app.py
```

Check the model IDs in `.env` against Google's current model list before a demo. They change often.

## Demo script (about 5 minutes)

1. **Generate tab** → *Load built-in sample cases*. Two cases load and verify instantly (SQL injection
   in Python, stack overflow in C), with no network needed.
2. **Cases tab** → open the C case. Show the vulnerable code next to the patched twin, then the
   verification log with the AddressSanitizer report.
3. **Generate tab** → pick a language and CWE → *Generate with Gemini and verify*. Talk through how
   verification decides whether the case is trustworthy.
4. **Scan & score tab** → *Run detectors* → walk through the scoreboard, and point out the
   same-model-bias caveat.

Tip: generate several cases before the demo. Live generation depends on the network and rate limits.

## Project layout

```
app.py               Streamlit UI
vulngen/
  catalog.py         languages, CWEs, scenarios, trigger contracts
  llm.py             Gemini: generate_case() and review_code()
  verify.py          sandboxed verification in Docker
  scanners.py        Semgrep, Bandit, Cppcheck, Gemini detector adapters
  scoring.py         per-case results and scoreboard
  store.py           SQLite + case folders, ground-truth line diff
  samples.py         loads samples/ into the store
samples/             two hand-written, known-good cases
sandbox/Dockerfile   python:3.12-slim + gcc
data/                created at runtime (SQLite DB and case files)
```

## Sandbox settings

Every verification run uses a fresh container with these settings:

- `--network none`
- `--read-only` root filesystem, with a small `/tmp` tmpfs
- `--cap-drop ALL` and `no-new-privileges`
- an unprivileged user (`65534`)
- memory, CPU, and process limits
- 20-second timeouts

Scanners are static and run on the host against the target file only. They never see the trigger or the ground truth.

## Known limitations (it's a starting point)

- **Scope:** single-file programs, two languages, and eight CWEs.
- **Ground truth:** "lines the patch changed" with a ±2-line tolerance. A patch that rewrites a lot
  of code widens the target. Unintended extra bugs in generated code aren't detected automatically
  (the full design runs a scanner panel over the patched twin to catch them).
- **Same-model bias:** Gemini generates and reviews. Add a second model family (for example a local Gemma
  via Ollama) as another detector to show the effect.
- **Semgrep setup:** rulesets download from the Semgrep registry, so the first scan needs internet.
- **Isolation:** Docker isolation is adequate for small demo code, not for untrusted workloads at scale
  (the full design uses Firecracker or gVisor).
- **Data use:** Gemini's free tier may use prompts to improve Google's products. That's fine for synthetic
  demo code, but use a paid key for anything proprietary.

## Ideas for next steps

- A CLI for batch generation (`python -m vulngen generate --n 20`)
- SARIF export of findings and ground truth
- A Gemma/Ollama detector, and generation with a second model family
- A difficulty tag per case (interprocedural depth, data-flow length), with stratified scores

"""Gemini calls: one to generate a test case, one to review code as a detector."""

import re

from google import genai
from google.genai import types

from . import config
from .catalog import CWES, LANGUAGES
from .models import Finding, GeneratedCase, Review

_client = None


def client() -> genai.Client:
    global _client
    if _client is None:
        if not config.GEMINI_API_KEY:
            raise RuntimeError("GEMINI_API_KEY is not set. Copy .env.example to .env and add your key.")
        _client = genai.Client(api_key=config.GEMINI_API_KEY)
    return _client


GEN_PROMPT = """You are generating one test case for an internal benchmark that measures how well \
security scanners and AI code reviewers detect vulnerabilities. The code is only ever executed inside \
an offline, isolated sandbox and is never deployed.

Write a small, realistic, self-contained {lang_label} program for this scenario: {scenario}.
It must contain exactly ONE intentional vulnerability of type {cwe}: {cwe_name}.

Requirements:
- A single source file, {stdlib_rule}, roughly 40 to 120 lines.
- Make it look like ordinary production code: realistic names, structure, and helper functions.
- Do NOT include comments, identifiers, or strings that hint at the vulnerability \
(no "vuln", "unsafe", "insecure", "bug", "TODO: sanitize", "exploit", and so on).
- patched_code must be identical to vulnerable_code except for the minimal change that fixes the flaw.
- Neither version may contain any other vulnerability.
- trigger: {trigger_contract}
- explanation: one or two sentences describing the flaw and where it is.
- Return raw source code with no markdown code fences.
"""

REVIEW_PROMPT = """You are a security code reviewer. Review the {lang_label} source file below and report \
every security vulnerability you find. For each one, give the 1-based line number where the flaw is, the \
most specific CWE identifier (for example CWE-89), and a short description. If you find nothing, return an \
empty list. Line numbers are shown at the left of each line; they are not part of the code.

{numbered_code}
"""

_FENCE = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*\n(.*?)\n\s*```\s*$", re.DOTALL)


def _strip_fences(text: str) -> str:
    m = _FENCE.match(text)
    return m.group(1) if m else text


def generate_case(language: str, cwe: str, scenario: str) -> GeneratedCase:
    lang = LANGUAGES[language]
    prompt = GEN_PROMPT.format(
        lang_label=lang["label"],
        scenario=scenario,
        cwe=cwe,
        cwe_name=CWES[language][cwe],
        stdlib_rule=lang["stdlib_rule"],
        trigger_contract=lang["trigger_contract"],
    )
    resp = client().models.generate_content(
        model=config.GEN_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=GeneratedCase,
            temperature=0.9,
        ),
    )
    case = resp.parsed if isinstance(resp.parsed, GeneratedCase) else GeneratedCase.model_validate_json(resp.text)
    case.vulnerable_code = _strip_fences(case.vulnerable_code)
    case.patched_code = _strip_fences(case.patched_code)
    case.trigger = _strip_fences(case.trigger)
    return case


def review_code(code: str, language: str) -> list[Finding]:
    numbered = "\n".join(f"{i:4d}| {line}" for i, line in enumerate(code.splitlines(), 1))
    prompt = REVIEW_PROMPT.format(lang_label=LANGUAGES[language]["label"], numbered_code=numbered)
    resp = client().models.generate_content(
        model=config.REVIEW_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=Review,
            temperature=0.0,
        ),
    )
    review = resp.parsed if isinstance(resp.parsed, Review) else Review.model_validate_json(resp.text)
    return review.findings

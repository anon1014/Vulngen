"""Load the hand-written sample cases, so the demo works without an API key or network."""

import json

from . import config, store
from .catalog import LANGUAGES
from .models import GeneratedCase


def load_samples() -> list[str]:
    ids = []
    for d in sorted(p for p in config.SAMPLES_DIR.iterdir() if p.is_dir()):
        meta = json.loads((d / "case.json").read_text())
        lang = meta["language"]
        ext = LANGUAGES[lang]["ext"]
        gc = GeneratedCase(
            title=meta["title"],
            vulnerable_code=(d / f"vulnerable.{ext}").read_text(),
            patched_code=(d / f"patched.{ext}").read_text(),
            trigger=(d / LANGUAGES[lang]["trigger_file"]).read_text(),
            explanation=meta["explanation"],
        )
        ids.append(store.save_case(gc, lang, meta["cwe"], source=f"sample:{d.name}"))
    return ids

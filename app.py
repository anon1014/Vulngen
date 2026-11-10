"""VulnGen demo UI.  Run with:  streamlit run app.py"""

import random

import pandas as pd
import streamlit as st

from vulngen import config, scoring, store, verify
from vulngen.catalog import CWES, LANGUAGES, SCENARIOS
from vulngen.scanners import TOOLS, available, run_tool
from vulngen.samples import load_samples

st.set_page_config(page_title="VulnGen demo", layout="wide")
st.title("VulnGen: verified vulnerable test cases for scoring detectors")
st.caption("Everything generated here is intentionally vulnerable. It is verified only inside an "
           "offline Docker sandbox and must never be deployed or published.")

# ---------------------------------------------------------------- sidebar: environment status
with st.sidebar:
    st.header("Environment")
    docker_ok = verify.docker_available()
    image_ok = docker_ok and verify.image_exists()
    st.write(("✅" if docker_ok else "❌") + " Docker running")
    st.write(("✅" if image_ok else "❌") + f" Sandbox image `{config.SANDBOX_IMAGE}`")
    if docker_ok and not image_ok and st.button("Build sandbox image"):
        with st.spinner("Building image (first time takes a minute)..."):
            ok, log = verify.build_image()
        (st.success if ok else st.error)("Built" if ok else "Build failed")
        st.code(log)
    st.write(("✅" if config.GEMINI_API_KEY else "❌") + " Gemini API key")
    st.caption(f"Generator: `{config.GEN_MODEL}`  \nReviewer: `{config.REVIEW_MODEL}`")
    st.subheader("Scanners")
    for tool, meta in TOOLS.items():
        st.write(("✅" if available(tool) else "❌") + f" {meta['label']}")


def show_case(case: dict) -> None:
    p = store.paths(case["id"], case["language"])
    status = {1: "✅ verified", 0: "❌ not verified", None: "⏳ not checked"}[case["verified"]]
    st.markdown(f"**{case['title']}** · {case['language']} · {case['cwe']} · {status}")
    st.caption(f"Ground truth: lines {case['vuln_lines']} — {case['explanation']}")
    lang = "python" if case["language"] == "python" else "c"
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("Vulnerable")
        st.code(p["vulnerable"].read_text(), language=lang, line_numbers=True)
    with c2:
        st.markdown("Patched twin")
        st.code(p["patched"].read_text(), language=lang, line_numbers=True)
    with st.expander("Trigger (hidden from detectors)"):
        st.code(p["trigger"].read_text(), language="python" if lang == "python" else "text")
    if case["verify_log"]:
        with st.expander("Verification log"):
            st.code(case["verify_log"], language="text")


tab_gen, tab_cases, tab_score = st.tabs(["1. Generate", "2. Cases", "3. Scan & score"])

# ---------------------------------------------------------------- 1. generate
with tab_gen:
    c1, c2, c3 = st.columns(3)
    language = c1.selectbox("Language", list(LANGUAGES), format_func=lambda k: LANGUAGES[k]["label"])
    cwe = c2.selectbox("Vulnerability", list(CWES[language]), format_func=lambda k: f"{k}: {CWES[language][k]}")
    scenario = c3.selectbox("Scenario", ["(random)"] + SCENARIOS)

    b1, b2 = st.columns([1, 1])
    if b1.button("Generate with Gemini and verify", type="primary", disabled=not config.GEMINI_API_KEY):
        from vulngen import llm

        chosen = random.choice(SCENARIOS) if scenario == "(random)" else scenario
        try:
            with st.spinner(f"Asking Gemini for {cwe} in {chosen}..."):
                gc = llm.generate_case(language, cwe, chosen)
            if llm.last_model_used != config.GEN_MODEL:
                st.info(f"{config.GEN_MODEL} was busy, so this case was generated with {llm.last_model_used}.")
            case_id = store.save_case(gc, language, cwe, source=f"gemini:{llm.last_model_used}")
            if image_ok:
                with st.spinner("Verifying in sandbox..."):
                    ok, _ = verify.verify_case(case_id)
                (st.success if ok else st.warning)(
                    "Verified: trigger works on the vulnerable version and fails on the patched one."
                    if ok else "Not verified. It is kept but excluded from scoring; see the log.")
            else:
                st.info("Saved, but not verified: the Docker sandbox isn't ready.")
            show_case(store.get_case(case_id))
        except Exception as e:
            st.error(f"Generation failed: {e}")

    if b2.button("Load built-in sample cases"):
        ids = load_samples()
        if image_ok:
            with st.spinner("Verifying samples in sandbox..."):
                for i in ids:
                    verify.verify_case(i)
        st.success(f"Loaded {len(ids)} sample cases. See the Cases tab.")

# ---------------------------------------------------------------- 2. cases
with tab_cases:
    cases = store.list_cases()
    if not cases:
        st.info("No cases yet. Generate one or load the samples.")
    else:
        df = pd.DataFrame(cases)[["id", "title", "language", "cwe", "verified", "source", "created"]]
        df["verified"] = df["verified"].map({1: "yes", 0: "no", None: "unchecked"})
        st.dataframe(df, hide_index=True, use_container_width=True)
        pick = st.selectbox("Inspect case", [c["id"] for c in cases],
                            format_func=lambda i: next(f"{c['title']} ({i})" for c in cases if c["id"] == i))
        case = store.get_case(pick)
        a, b, _ = st.columns([1, 1, 4])
        if a.button("Re-verify", disabled=not image_ok):
            with st.spinner("Verifying..."):
                verify.verify_case(pick)
            case = store.get_case(pick)
        if b.button("Delete case"):
            store.delete_case(pick)
            st.rerun()
        show_case(case)

# ---------------------------------------------------------------- 3. scan & score
with tab_score:
    verified = [c for c in store.list_cases() if c["verified"]]
    st.write(f"{len(verified)} verified cases are eligible for scoring.")
    usable = [t for t in TOOLS if available(t)]
    tools = st.multiselect("Detectors", usable, default=usable, format_func=lambda t: TOOLS[t]["label"])

    if st.button("Run detectors on all verified cases", type="primary", disabled=not (verified and tools)):
        jobs = [(c, t, v) for c in verified for t in tools if c["language"] in TOOLS[t]["languages"]
                for v in ("vulnerable", "patched")]
        bar = st.progress(0.0)
        errors = []
        for n, (case, tool, variant) in enumerate(jobs, 1):
            path = store.paths(case["id"], case["language"])[variant]
            bar.progress(n / len(jobs), text=f"{TOOLS[tool]['label']} on {case['title']} ({variant})")
            try:
                store.record_scan(case["id"], tool, variant, "ok", run_tool(tool, path, case["language"]))
            except Exception as e:
                store.record_scan(case["id"], tool, variant, f"error: {e}", [])
                errors.append(f"{tool} / {case['id']} / {variant}: {e}")
        bar.empty()
        if errors:
            with st.expander(f"{len(errors)} scanner errors"):
                st.code("\n".join(errors), language="text")

    detail = scoring.per_case(store.list_cases(), store.all_findings(), store.all_scans())
    if detail.empty:
        st.info("No scan results yet.")
    else:
        board = scoring.scoreboard(detail)
        st.subheader("Scoreboard")
        st.dataframe(
            board.style.format({
                "Detection rate": "{:.0%}", "Exact-CWE rate": "{:.0%}",
                "Patch false-alarm rate": "{:.0%}", "Avg other findings": "{:.1f}",
            }, na_rep="–"),
            use_container_width=True,
        )
        st.bar_chart(board[["Detection rate", "Patch false-alarm rate"]])
        st.warning("Caveat: Gemini both generated these cases and reviewed them, which tends to inflate "
                   "its score (same-model bias). The full design generates with several model families.")
        with st.expander("Per-case results"):
            st.dataframe(detail, hide_index=True, use_container_width=True)
        with st.expander("Raw findings"):
            st.dataframe(pd.DataFrame(store.all_findings()), hide_index=True, use_container_width=True)

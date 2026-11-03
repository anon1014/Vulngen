"""Prove each case is real: the trigger must work on the vulnerable version and fail on the patched one.

Everything runs in a throwaway Docker container with no network, a read-only root filesystem,
no Linux capabilities, an unprivileged user, and CPU/memory/process limits.
"""

import shutil
import subprocess
import uuid

from . import config, store

DOCKER_BASE = [
    "docker", "run", "--rm",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "128",
    "--memory", "512m",
    "--cpus", "1",
    "--user", "65534:65534",
]


def docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except Exception:
        return False


def image_exists() -> bool:
    r = subprocess.run(["docker", "image", "inspect", config.SANDBOX_IMAGE], capture_output=True)
    return r.returncode == 0


def build_image() -> tuple[bool, str]:
    r = subprocess.run(
        ["docker", "build", "-t", config.SANDBOX_IMAGE, str(config.SANDBOX_DIR)],
        capture_output=True, text=True,
    )
    return r.returncode == 0, (r.stdout + r.stderr)[-4000:]


def _run(variant_dir, trigger_path, language: str) -> tuple[int, str, str]:
    name = f"vulngen-{uuid.uuid4().hex[:10]}"
    cmd = DOCKER_BASE + [
        "--name", name,
        "-v", f"{variant_dir.resolve()}:/case:ro",
        "-v", f"{trigger_path.resolve()}:/trigger/{trigger_path.name}:ro",
    ]
    if language == "python":
        cmd += ["-e", "PYTHONPATH=/case", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
                config.SANDBOX_IMAGE, "timeout", "20", "python", "/trigger/trigger.py"]
    else:
        script = (
            "gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -o /tmp/target /case/target.c "
            "&& timeout 20 /tmp/target < /trigger/trigger.txt"
        )
        cmd += ["-e", "ASAN_OPTIONS=detect_leaks=0", config.SANDBOX_IMAGE, "sh", "-c", script]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "kill", name], capture_output=True)
        return -1, "", "Timed out"


def verify_case(case_id: str) -> tuple[bool, str]:
    case = store.get_case(case_id)
    lang = case["language"]
    p = store.paths(case_id, lang)

    rc_v, out_v, err_v = _run(p["vulnerable"].parent, p["trigger"], lang)
    rc_p, out_p, err_p = _run(p["patched"].parent, p["trigger"], lang)

    if lang == "python":
        vuln_fires = "EXPLOITED" in out_v.split()
        patch_fires = "EXPLOITED" in out_p.split()
        ok = vuln_fires and not patch_fires
        verdict = (f"Vulnerable version exploited: {vuln_fires}\n"
                   f"Patched version exploited: {patch_fires}")
    else:
        vuln_fires = rc_v != 0 and "AddressSanitizer" in err_v
        patch_clean = rc_p == 0 and "AddressSanitizer" not in err_p
        ok = vuln_fires and patch_clean
        verdict = (f"Vulnerable build hit AddressSanitizer: {vuln_fires}\n"
                   f"Patched build ran cleanly: {patch_clean}")

    log = (
        f"{'VERIFIED' if ok else 'NOT VERIFIED'}\n{verdict}\n\n"
        f"--- vulnerable (exit {rc_v}) ---\n{out_v[-1500:]}\n{err_v[-2500:]}\n\n"
        f"--- patched (exit {rc_p}) ---\n{out_p[-1500:]}\n{err_p[-2500:]}"
    )
    store.set_verified(case_id, ok, log)
    return ok, log

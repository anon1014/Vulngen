"""Languages, vulnerability types, and scenario ideas the demo supports."""

LANGUAGES = {
    "python": {
        "label": "Python",
        "ext": "py",
        "trigger_file": "trigger.py",
        "stdlib_rule": "Python 3 standard library only (no third-party packages)",
        "trigger_contract": (
            "a Python script that will be saved as trigger.py next to the program, which is saved as "
            "target.py. It imports from target, exercises the vulnerability, and prints exactly the word "
            "EXPLOITED (on its own line) only if the attack succeeded. Run against the patched version it "
            "must NOT print EXPLOITED. Standard library only, no network access, create files only under "
            "/tmp, and finish in under 5 seconds. The program itself must not run anything at import time "
            "(put any demo entry point under `if __name__ == '__main__':`)."
        ),
    },
    "c": {
        "label": "C",
        "ext": "c",
        "trigger_file": "trigger.txt",
        "stdlib_rule": "C11 using only the standard C library, defining main()",
        "trigger_contract": (
            "plain text (printable ASCII, newlines allowed) that will be fed to the program on standard "
            "input. The program is saved as target.c and compiled with "
            "`gcc -g -O0 -fsanitize=address`. The trigger must make the vulnerable build abort with an "
            "AddressSanitizer error. The patched build must handle the same input and exit with status 0. "
            "The program must read its input only from stdin and must not open files or sockets."
        ),
    },
}

CWES = {
    "python": {
        "CWE-89": "SQL injection (use the sqlite3 module with an in-memory database)",
        "CWE-22": "Path traversal (reading files relative to a base directory under /tmp)",
        "CWE-78": "OS command injection",
        "CWE-502": "Deserialization of untrusted data",
    },
    "c": {
        "CWE-121": "Stack-based buffer overflow",
        "CWE-122": "Heap-based buffer overflow",
        "CWE-416": "Use after free",
        "CWE-190": "Integer overflow that leads to an out-of-bounds write",
    },
}

SCENARIOS = [
    "an internal user directory lookup",
    "a log file viewer for a support team",
    "a configuration file parser",
    "an inventory and stock-level tool",
    "a simple ticketing system",
    "a CSV report importer",
    "a URL shortener backend",
    "a command-line note-taking tool",
    "a sensor data packet decoder",
    "a small key-value cache",
]

#!/usr/bin/env python3
"""Require real named provider regressions when original tuple guards return."""
import os
from pathlib import Path
import re
import subprocess

SOURCE = 'src/engine.rs'
TARGET = 'gates'
TEST = 'distinct_signed_voucher_providers_coexist_in_memory_and_sql'
CONTROLS = ((b'                gate.result.gate.clone(),\n                gate.result.provider.clone(),', b'                gate.result.gate.clone(),', 'distinct authenticated providers must coexist'), (b'                    || old.result.provider != gate.result.provider', b'', 'fresh evidence must preserve other authenticated providers'))


def run():
    result = subprocess.run(
        ["cargo", "test", "--locked", "--test", TARGET, TEST,
         "--", "--exact", "--nocapture"], capture_output=True, text=True,
        timeout=900,
        env={**os.environ, "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"},
    )
    return result.returncode, result.stdout + result.stderr


def exact_result(output, result):
    return re.search(r"^test " + re.escape(TEST) + r" \.\.\. " + result + r"$",
                     output, re.M) is not None


def baseline(status, output):
    return (status == 0 and exact_result(output, "ok")
            and "test result: ok. 1 passed; 0 failed; 0 ignored;" in output)


def assertion(status, output, marker):
    # Build failures, unrelated assertions and zero selected tests cannot qualify.
    return (status == 101 and exact_result(output, "FAILED")
            and "test result: FAILED. 0 passed; 1 failed; 0 ignored;" in output
            and re.search(r"thread '" + re.escape(TEST)
                          + r"'(?: \([0-9]+\))? panicked at tests/"
                          + re.escape(TARGET) + r"\.rs:[0-9]+:[0-9]+:", output)
            and marker in output and "error[E" not in output
            and "could not compile" not in output)


def main():
    path = Path(SOURCE)
    original = path.read_bytes()
    for before, after, marker in CONTROLS:
        if original.count(before) != 1:
            raise SystemExit("Provider control source drift: " + marker)
        status, output = run()
        if not baseline(status, output):
            print(output)
            raise SystemExit("Provider control needs a passing exact baseline")
        try:
            path.write_bytes(original.replace(before, after))
            status, output = run()
            if not assertion(status, output, marker):
                print(output)
                raise SystemExit("Old provider behavior did not fail its named assertion")
            print("Old provider behavior rejected by named assertion: " + marker)
        finally:
            path.write_bytes(original)
        if path.read_bytes() != original:
            raise SystemExit("Provider control source restoration failed")


if __name__ == "__main__":
    main()

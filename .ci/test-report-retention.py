#!/usr/bin/env python3
"""Exercise the real verification shell without invoking any compiler or provider."""
from pathlib import Path
import os
import subprocess
import tempfile

SOURCE = Path(__file__).with_name("verify.sh").read_bytes()
REPORTS = ("coverage.json", "coverage.lcov", "coverage.txt")
STUB = r'''#!/usr/bin/env bash
set -euo pipefail
case "${0##*/}" in
  cargo)
    case "$1" in
      metadata) printf '{}\n' ;;
      check)
        if [[ "$FIXTURE_CASE" == probe_compiles ]]; then exit 0; fi
        printf 'could not find `development` in `gates`\n'
        exit 1
        ;;
      llvm-cov)
        while (( $# )); do
          if [[ "$1" == --output-path ]]; then
            printf 'fixture report: %s\n' "$2" > "$2"
            break
          fi
          shift
        done
        ;;
    esac
    ;;
  rustup)
    if [[ "$1" == which ]]; then printf '%s/%s\n' "$STUB_BIN" "$4"; fi
    ;;
  python3)
    if [[ "$1" == .github/check-source-coverage.py && "$FIXTURE_CASE" == coverage_fails ]]; then exit 7; fi
    ;;
esac
'''

for case, expected in (("success", 0), ("coverage_fails", 7), ("probe_compiles", 1), ("probe_exists", 2)):
    with tempfile.TemporaryDirectory(prefix="cgts-report-retention-") as directory:
        root = Path(directory)
        binaries = root / "bin"
        binaries.mkdir()
        for command in ("cargo", "rustc", "rustup", "node", "python3"):
            stub = binaries / command
            stub.write_text(STUB)
            stub.chmod(0o755)
        (root / ".ci").mkdir()
        (root / ".ci/verify.sh").write_bytes(SOURCE)
        # The script advances our own crates through cargo; the scenario stubs cargo, so a no-op stands in.
        (root / ".ci/update-our-crates.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
        (root / ".ci/development_gate_probe.rs").write_bytes(b"fixture probe\n")
        artifacts = root / "artifacts"
        artifacts.mkdir()
        probe = root / "examples/development_gate_probe.rs"
        if case == "probe_exists":
            probe.parent.mkdir()
            probe.write_bytes(b"existing caller file\n")
        # Existing output must also survive a failure before coverage executes.
        for report in REPORTS:
            (root / report).write_text(f"fixture report: {report}\n")
        environment = dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}",
                           ARTIFACT_ROOT=str(artifacts), STUB_BIN=str(binaries), FIXTURE_CASE=case)
        result = subprocess.run(["bash", ".ci/verify.sh"], cwd=root, env=environment,
                                capture_output=True, text=True)
        assert result.returncode == expected, (case, result.returncode, result.stdout, result.stderr)
        for report in REPORTS:
            assert (artifacts / report).read_bytes() == (root / report).read_bytes(), (case, report)
        if case == "probe_exists":
            assert probe.read_bytes() == b"existing caller file\n"
        else:
            assert not probe.exists(), case
print("Complete verification-script report retention: 4 inert scenarios passed")

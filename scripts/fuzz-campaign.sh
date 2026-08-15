#!/usr/bin/env bash
#
# Run a bounded, auditable fuzz campaign across EnvVault's libFuzzer targets.
# Linux/macOS port of scripts/fuzz-campaign.ps1.
#
# For each target this script:
#   1. Runs `cargo fuzz run` for a bounded duration.
#   2. Minimizes the persistent corpus in place (unless --skip-minimize).
#   3. Optionally generates an llvm-cov line-coverage report (unless
#      --skip-coverage).
#   4. Emits a value-free run record (JSON + Markdown) under fuzz/runs/<ts>/.
#
# Requires: a nightly toolchain and cargo-fuzz on PATH. This script never
# emits, collects, or commits secret values; generated run directories and
# coverage data are git-ignored work products.

set -euo pipefail

SECONDS_PER_TARGET=900
MAX_LEN=32768
TARGETS=(vault identity_audit policy_profile dotenv)
SKIP_MINIMIZE=0
SKIP_COVERAGE=0
RUNS_ROOT="fuzz/runs"

usage() {
    cat <<'EOF'
Usage: fuzz-campaign.sh [options]

  --seconds-per-target <s>   Seconds to fuzz each target (default 900).
  --max-len <n>              Maximum input length passed to libFuzzer (default 32768).
  --targets <a,b,c>          Comma-separated targets to run.
  --skip-minimize            Do not minimize the persistent corpus.
  --skip-coverage            Do not generate line-coverage reports.
  --runs-root <dir>          Run-record directory (default fuzz/runs).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --seconds-per-target) SECONDS_PER_TARGET="$2"; shift 2 ;;
        --max-len) MAX_LEN="$2"; shift 2 ;;
        --targets) IFS=',' read -r -a TARGETS <<<"$2"; shift 2 ;;
        --skip-minimize) SKIP_MINIMIZE=1; shift ;;
        --skip-coverage) SKIP_COVERAGE=1; shift ;;
        --runs-root) RUNS_ROOT="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "fuzz-campaign.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

command -v cargo-fuzz >/dev/null 2>&1 || { echo 'cargo-fuzz not found on PATH' >&2; exit 2; }

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
FUZZ_DIR="$REPO_ROOT/fuzz"
CORPUS_ROOT="$FUZZ_DIR/corpus"

for target in "${TARGETS[@]}"; do
    [ -d "$CORPUS_ROOT/$target" ] || {
        echo "Corpus directory not found for target '$target': $CORPUS_ROOT/$target" >&2
        exit 2
    }
done

echo '==> Building fuzz targets'
cargo fuzz build

started_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
run_id=$(date -u +%Y%m%d-%H%M%S)
run_dir="$REPO_ROOT/$RUNS_ROOT/$run_id"
logs_dir="$run_dir/logs"
artifacts_dir="$run_dir/artifacts"
coverage_dir="$run_dir/coverage"
mkdir -p "$logs_dir" "$artifacts_dir" "$coverage_dir"

rustc_version=$(rustc --version 2>/dev/null | sed 's/^rustc //')
cargo_fuzz_version=$(cargo fuzz --version 2>/dev/null | head -1 || true)
host_triple=$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')

corpus_count() {
    local dir="$1" n=0
    if [ -d "$dir" ]; then
        n=$(find "$dir" -maxdepth 1 -type f ! -name '.gitkeep' | wc -l | tr -d ' ')
    fi
    printf '%s' "$n"
}

results_file="$run_dir/results.jsonl"
: >"$results_file"

for target in "${TARGETS[@]}"; do
    echo "==> Fuzzing target: $target"
    log_file="$logs_dir/$target.log"
    corpus_dir="$CORPUS_ROOT/$target"
    target_artifact_dir="$FUZZ_DIR/artifacts/$target"
    run_artifact_dir="$artifacts_dir/$target"
    mkdir -p "$run_artifact_dir"

    corpus_before=$(corpus_count "$corpus_dir")
    artifacts_before=()
    if [ -d "$target_artifact_dir" ]; then
        mapfile -t artifacts_before < <(find "$target_artifact_dir" -maxdepth 1 -type f -printf '%f\n' | sort)
    fi

    set +e
    cargo fuzz run "$target" -- "-max_total_time=$SECONDS_PER_TARGET" "-max_len=$MAX_LEN" >"$log_file" 2>&1
    run_exit=$?
    set -e

    new_artifacts=()
    if [ -d "$target_artifact_dir" ]; then
        mapfile -t new_artifacts < <(comm -13 <(printf '%s\n' "${artifacts_before[@]}" | sort) \
            <(find "$target_artifact_dir" -maxdepth 1 -type f -printf '%f\n' | sort))
    fi
    for a in "${new_artifacts[@]}"; do
        cp "$target_artifact_dir/$a" "$run_artifact_dir/$a"
    done

    if [ "$SKIP_MINIMIZE" -eq 0 ]; then
        echo "    Minimizing corpus: $corpus_dir"
        cargo fuzz cmin "$target" "$corpus_dir"
    fi

    corpus_after=$(corpus_count "$corpus_dir")

    coverage="null"
    coverage_log="$logs_dir/$target.coverage.log"
    if [ "$SKIP_COVERAGE" -eq 0 ]; then
        echo "    Generating coverage: $target"
        : >"$coverage_log"

        sysroot=$(rustc --print sysroot 2>/dev/null)
        llvm_cov=$(find "$sysroot/lib/rustlib" -type f -name 'llvm-cov*' 2>/dev/null | head -1 || true)
        llvm_profdata=$(find "$sysroot/lib/rustlib" -type f -name 'llvm-profdata*' 2>/dev/null | head -1 || true)

        # Build the coverage-instrumented binary against a one-seed mini corpus
        # so the build step stays fast; the real corpus is profiled separately
        # in directory mode below (one argv entry, no command-line explosion).
        mini_dir=$(mktemp -d)
        first_seed=$(find "$corpus_dir" -maxdepth 1 -type f ! -name '.gitkeep' | head -1 || true)
        if [ -n "$first_seed" ]; then cp "$first_seed" "$mini_dir/"; fi
        set +e
        cargo fuzz coverage "$target" "$mini_dir" >>"$coverage_log" 2>&1
        set -e
        rm -rf "$mini_dir"

        coverage_bin=$(find "$REPO_ROOT/target" -type f -path "*/coverage/*/release/$target" 2>/dev/null | head -1 || true)

        if [ -n "$llvm_cov" ] && [ -n "$llvm_profdata" ] && [ -n "$coverage_bin" ]; then
            profraw_pattern="$coverage_dir/$target-%p.profraw"
            if LLVM_PROFILE_FILE="$profraw_pattern" "$coverage_bin" -runs=0 "$corpus_dir" >>"$coverage_log" 2>&1; then
                profdata="$FUZZ_DIR/coverage/$target/coverage.profdata"
                mkdir -p "$(dirname "$profdata")"
                "$llvm_profdata" merge -sparse "$coverage_dir"/"$target"-*.profraw -o "$profdata" >>"$coverage_log" 2>&1
                report_file="$coverage_dir/$target.txt"
                html_dir="$coverage_dir/$target-html"
                "$llvm_cov" report "$coverage_bin" "-instr-profile=$profdata" \
                    '-ignore-filename-regex=registry|toolchains|rustlib' \
                    | sed 's/\x1b\[[0-9;]*m//g' >"$report_file" 2>>"$coverage_log"
                "$llvm_cov" show "$coverage_bin" "-instr-profile=$profdata" \
                    '-ignore-filename-regex=registry|toolchains|rustlib' \
                    -format=html "-output-dir=$html_dir" >>"$coverage_log" 2>&1
                total=$(grep '^TOTAL' "$report_file" 2>/dev/null | tail -1 || true)
                coverage=$(jq -nc \
                    --arg report "coverage/$target.txt" \
                    --arg html "coverage/$target-html" \
                    --arg total "${total:-unavailable}" \
                    '{report:$report, html:$html, total:$total}')
            else
                note="coverage profile run failed; see $coverage_log"
                coverage=$(jq -nc --arg note "$note" '{report:null, html:null, total:"unavailable", note:$note}')
            fi
        else
            note="coverage tools or instrumented binary not found"
            coverage=$(jq -nc --arg note "$note" '{report:null, html:null, total:"unavailable", note:$note}')
            echo "WARNING: coverage skipped for '$target': $note" >&2
        fi
    fi

    if [ "${#new_artifacts[@]}" -gt 0 ]; then
        status='artifacts_found'
    elif [ "$run_exit" -ne 0 ]; then
        status='run_failed'
    else
        status='clean'
    fi

    jq -nc \
        --arg target "$target" \
        --arg status "$status" \
        --argjson run_exit "$run_exit" \
        --argjson corpus_before "$corpus_before" \
        --argjson corpus_after "$corpus_after" \
        --argjson new_artifacts "$(jq -nc --args '$ARGS.positional' "${new_artifacts[@]}")" \
        --argjson coverage "$coverage" \
        --arg log "logs/$target.log" \
        '{target:$target, status:$status, run_exit_code:$run_exit,
          corpus_before:$corpus_before, corpus_after:$corpus_after,
          new_artifacts:$new_artifacts, coverage:$coverage, log:$log}' \
        >>"$results_file"
done

finished_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)

overall=$(jq -s -r '
  if any(.[]; .status == "artifacts_found") then "artifacts_found"
  elif any(.[]; .status == "run_failed") then "run_failed"
  else "clean" end' "$results_file")

jq -s \
    --arg started "$started_utc" \
    --arg finished "$finished_utc" \
    --arg rustc "$rustc_version" \
    --arg cargo_fuzz "$cargo_fuzz_version" \
    --argjson seconds "$SECONDS_PER_TARGET" \
    --argjson max_len "$MAX_LEN" \
    --argjson minimize "$([ "$SKIP_MINIMIZE" -eq 0 ] && echo true || echo false)" \
    --argjson coverage "$([ "$SKIP_COVERAGE" -eq 0 ] && echo true || echo false)" \
    --argjson targets "$(jq -nc --args '$ARGS.positional' "${TARGETS[@]}")" \
    --arg overall "$overall" \
    '{schema:"envvault-fuzz-run-v1", started_at_utc:$started, finished_at_utc:$finished,
      toolchain:$rustc, cargo_fuzz:$cargo_fuzz, host:{os:"linux"},
      parameters:{seconds_per_target:$seconds, max_len:$max_len, targets:$targets,
        minimize:$minimize, coverage:$coverage},
      overall:$overall, results:.}' \
    "$results_file" >"$run_dir/run.json"

{
    printf '# EnvVault Fuzz Run Record\n\n'
    printf -- '- Run: `%s`\n' "$run_id"
    printf -- '- Started (UTC): `%s`\n' "$started_utc"
    printf -- '- Finished (UTC): `%s`\n' "$finished_utc"
    printf -- '- Toolchain: `%s`\n' "$rustc_version"
    printf -- '- cargo-fuzz: `%s`\n' "$cargo_fuzz_version"
    printf -- '- Parameters: `%s` s/target, max_len `%s`\n' "$SECONDS_PER_TARGET" "$MAX_LEN"
    printf -- '- Overall: `%s`\n\n' "$overall"
    printf '## Results\n\n'
    printf '| Target | Status | Corpus before | Corpus after | New artifacts | Coverage total |\n'
    printf '|---|---|---:|---:|---:|---|\n'
    jq -r '.results[] | "| \(.target) | \(.status) | \(.corpus_before) | \(.corpus_after) | \(.new_artifacts | length) | \(.coverage.total // "-") |"' "$run_dir/run.json"
    printf '\n## Notes\n\n'
    printf -- '- "artifacts_found" means libFuzzer produced crash/timeout/OOM artifacts; review them before reuse.\n'
    printf -- '- Minimized corpus is written in place under `fuzz/corpus/<target>`; review and commit intentionally.\n'
    printf -- '- Coverage percentages cover the `envvault` crate sources only; third-party code is filtered out.\n'
} >"$run_dir/run.md"

echo ''
echo "==> Run record: $run_dir/run.json"
echo "==> Markdown:   $run_dir/run.md"
echo "==> Overall:    $overall"

if [ "$overall" != 'clean' ]; then
    exit 1
fi

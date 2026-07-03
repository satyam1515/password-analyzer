"""
==========================================================
run_all_analysis.py
==========================================================
Master Runner Script for the Research Analysis Pipeline.

This script runs all analysis scripts in the correct order,
producing datasets, graphs, statistical results, and reports.

Research Project: A Comparative Analysis of Password Strength
Metrics: Rules-Based vs. Entropy-Based Evaluation

Usage:
    python run_all_analysis.py          # Run all steps
    python run_all_analysis.py --step 1 # Run a specific step
    python run_all_analysis.py --from 3 # Run from step 3 onward


==========================================================
"""

import os
import sys
import time
import subprocess
import argparse
from datetime import datetime

# ── Project root ────────────────────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_ROOT)

# ── ANSI colours for terminal output ────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════
# PIPELINE DEFINITION
# ══════════════════════════════════════════════════════════════════

PIPELINE = [
    {
        "step": 1,
        "name": "Dataset Collection",
        "script": os.path.join("datasets", "collect_datasets.py"),
        "description": "Generate synthetic password dataset (~10,000 passwords)",
    },
    {
        "step": 2,
        "name": "Data Cleaning & Feature Engineering",
        "script": os.path.join("datasets", "clean_datasets.py"),
        "description": "Clean data, compute all metric scores, generate statistics",
    },
    {
        "step": 3,
        "name": "Exploratory Data Analysis",
        "script": os.path.join("analysis", "eda_analysis.py"),
        "description": "Generate histograms, pie charts, frequency distributions",
    },
    {
        "step": 4,
        "name": "Classification Analysis",
        "script": os.path.join("analysis", "classification_analysis.py"),
        "description": "Confusion matrices, false positives, Accuracy/Precision/Recall/F1",
    },
    {
        "step": 5,
        "name": "Hash Generation",
        "script": os.path.join("cracking_environment", "generate_hashes.py"),
        "description": "Generate MD5, SHA1, SHA256 hashes for all passwords",
    },
    {
        "step": 6,
        "name": "Dictionary Attack Simulation",
        "script": os.path.join("cracking_environment", "dictionary_attack.py"),
        "description": "Simulate dictionary attack, measure success rates",
    },
    {
        "step": 7,
        "name": "Pattern Attack Analysis",
        "script": os.path.join("cracking_environment", "pattern_attack.py"),
        "description": "Test pattern-based passwords, compare crack rates",
    },
    {
        "step": 8,
        "name": "Time-to-Crack Analysis",
        "script": os.path.join("analysis", "ttc_analysis.py"),
        "description": "Calculate estimated TTC, generate TTC graphs",
    },
    {
        "step": 9,
        "name": "Statistical Analysis",
        "script": os.path.join("analysis", "statistical_analysis.py"),
        "description": "Pearson/Spearman correlations, heatmaps",
    },
    {
        "step": 10,
        "name": "Regression Analysis",
        "script": os.path.join("regression_analysis", "regression_model.py"),
        "description": "Linear regression, feature importance chart",
    },
    {
        "step": 11,
        "name": "Hybrid Model Comparison",
        "script": os.path.join("hybrid_model", "hybrid_research_model.py"),
        "description": "Person 2 hybrid model (30/30/20/10/10) vs Person 1 (30/30/30/10)",
    },
    {
        "step": 12,
        "name": "NIST & Microsoft Benchmarking",
        "script": os.path.join("benchmarking", "nist_benchmark.py"),
        "description": "Benchmark against NIST 800-63B and Microsoft guidelines",
    },
]


# ══════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════

def print_banner():
    """Print the research project banner."""
    print()
    print(f"{CYAN}{'=' * 66}{RESET}")
    print(f"{BOLD}{CYAN}  🔬 Password Strength Research — Analysis Pipeline{RESET}")
    print(f"{CYAN}  A Comparative Analysis of Password Strength Metrics{RESET}")
    print(f"{CYAN}  Rules-Based vs. Entropy-Based Evaluation{RESET}")
    print(f"{CYAN}{'=' * 66}{RESET}")
    print(f"  Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Project root: {PROJECT_ROOT}")
    print()


def run_step(step_info, step_num, total):
    """Run a single pipeline step."""
    name   = step_info["name"]
    script = step_info["script"]
    desc   = step_info["description"]

    print(f"\n{CYAN}{'─' * 66}{RESET}")
    print(f"{BOLD}  [{step_num}/{total}] {name}{RESET}")
    print(f"  {desc}")
    print(f"  Script: {script}")
    print(f"{CYAN}{'─' * 66}{RESET}\n")

    # Check if script exists
    script_path = os.path.join(PROJECT_ROOT, script)
    if not os.path.exists(script_path):
        print(f"  {RED}✗ Script not found: {script}{RESET}")
        print(f"  {YELLOW}  Skipping...{RESET}")
        return False, 0

    # Run the script
    start_time = time.time()
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            cwd=PROJECT_ROOT,
            capture_output=False,
            text=True,
            timeout=600,  # 10-minute timeout per step
        )
        elapsed = time.time() - start_time

        if result.returncode == 0:
            print(f"\n  {GREEN}✓ {name} completed in {elapsed:.1f}s{RESET}")
            return True, elapsed
        else:
            print(f"\n  {RED}✗ {name} failed (exit code {result.returncode}){RESET}")
            return False, elapsed

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start_time
        print(f"\n  {RED}✗ {name} timed out after {elapsed:.0f}s{RESET}")
        return False, elapsed
    except Exception as e:
        elapsed = time.time() - start_time
        print(f"\n  {RED}✗ {name} error: {e}{RESET}")
        return False, elapsed


def run_pipeline(steps_to_run):
    """Run the specified pipeline steps."""
    print_banner()

    total = len(steps_to_run)
    results = []

    for i, step_info in enumerate(steps_to_run, 1):
        success, elapsed = run_step(step_info, i, total)
        results.append({
            "step": step_info["step"],
            "name": step_info["name"],
            "success": success,
            "elapsed": elapsed,
        })

    # ── Print summary ───────────────────────────────────────────
    print(f"\n\n{CYAN}{'═' * 66}{RESET}")
    print(f"{BOLD}  📊 PIPELINE SUMMARY{RESET}")
    print(f"{CYAN}{'═' * 66}{RESET}\n")

    total_time = sum(r["elapsed"] for r in results)
    passed = sum(1 for r in results if r["success"])
    failed = sum(1 for r in results if not r["success"])

    for r in results:
        icon = f"{GREEN}✓{RESET}" if r["success"] else f"{RED}✗{RESET}"
        print(f"  {icon}  Step {r['step']:2d}: {r['name']:<40s} ({r['elapsed']:.1f}s)")

    print(f"\n  {GREEN}Passed: {passed}{RESET}  |  {RED}Failed: {failed}{RESET}  |  Total time: {total_time:.1f}s")
    print(f"\n  Graphs saved to:   {os.path.join(PROJECT_ROOT, 'graphs')}")
    print(f"  Datasets saved to: {os.path.join(PROJECT_ROOT, 'datasets')}")
    print(f"  Report saved to:   {os.path.join(PROJECT_ROOT, 'report')}")
    print()

    return failed == 0


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the Password Strength Research Analysis Pipeline"
    )
    parser.add_argument(
        "--step", type=int, default=None,
        help="Run only a specific step (1-12)"
    )
    parser.add_argument(
        "--from", dest="from_step", type=int, default=None,
        help="Run from a specific step onward (e.g., --from 3)"
    )
    parser.add_argument(
        "--to", type=int, default=None,
        help="Run up to a specific step (e.g., --to 5)"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List all pipeline steps without running"
    )

    args = parser.parse_args()

    # List mode
    if args.list:
        print_banner()
        print(f"  {BOLD}Pipeline Steps:{RESET}\n")
        for step in PIPELINE:
            print(f"  Step {step['step']:2d}: {step['name']}")
            print(f"           {step['description']}")
            print(f"           Script: {step['script']}\n")
        sys.exit(0)

    # Determine which steps to run
    if args.step is not None:
        steps = [s for s in PIPELINE if s["step"] == args.step]
        if not steps:
            print(f"{RED}Error: Step {args.step} not found.{RESET}")
            sys.exit(1)
    else:
        from_step = args.from_step or 1
        to_step = args.to or 12
        steps = [s for s in PIPELINE if from_step <= s["step"] <= to_step]

    success = run_pipeline(steps)
    sys.exit(0 if success else 1)

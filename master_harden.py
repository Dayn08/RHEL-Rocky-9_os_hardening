#!/usr/bin/env python3
"""
master_harden.py — Server Hardening Orchestrator
Supports: Red Hat Enterprise Linux 9 / Rocky Linux 9

Usage:
    sudo python3 master_harden.py
    sudo python3 master_harden.py --modules 01_gpg_check.sh 02_ssh.sh
    sudo python3 master_harden.py --dry-run
"""

import subprocess
import sys
import os
import argparse
import datetime
import glob

# ── Colour codes (auto-disabled if not a TTY) ─────────────────────────────────
USE_COLOR = sys.stdout.isatty()

def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

def green(t):   return _c("0;32", t)
def red(t):     return _c("0;31", t)
def yellow(t):  return _c("0;33", t)
def cyan(t):    return _c("0;36", t)
def bold(t):    return _c("1",    t)
def dim(t):     return _c("2",    t)

# ── Constants ─────────────────────────────────────────────────────────────────
SCRIPT_DIR   = os.path.dirname(os.path.realpath(__file__))
MODULES_DIR  = os.path.join(SCRIPT_DIR, "modules")
LOGS_DIR     = os.path.join(SCRIPT_DIR, "logs")
TIMESTAMP    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE     = os.path.join(LOGS_DIR, f"harden_{TIMESTAMP}.log")

EXIT_PASS    = 0
EXIT_FAIL    = 1
EXIT_SKIP    = 2

STATUS_LABEL = {
    EXIT_PASS: green("PASS"),
    EXIT_FAIL: red("FAIL"),
    EXIT_SKIP: yellow("SKIP"),
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def ensure_dirs():
    os.makedirs(MODULES_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR,    exist_ok=True)

def print_banner():
    print()
    print(bold("=" * 62))
    print(bold("  Server Hardening Orchestrator"))
    print(bold("  RHEL 9 / Rocky Linux 9"))
    print(bold(f"  Started : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print(bold("=" * 62))
    print()

def discover_modules(selected=None):
    """Return sorted list of .sh scripts from modules/."""
    all_scripts = sorted(glob.glob(os.path.join(MODULES_DIR, "*.sh")))
    if selected:
        all_scripts = [
            os.path.join(MODULES_DIR, s) if not os.path.isabs(s) else s
            for s in selected
        ]
    return all_scripts

def run_module(script_path, dry_run=False):
    """
    Execute a single hardening module.
    Returns (exit_code, stdout, stderr).
    """
    if not os.path.isfile(script_path):
        return EXIT_FAIL, "", f"Script not found: {script_path}"

    os.chmod(script_path, 0o750)

    if dry_run:
        return EXIT_SKIP, "[dry-run] would execute", ""

    result = subprocess.run(
        ["bash", script_path],
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def log_write(log_fh, module_name, code, stdout, stderr):
    log_fh.write(f"\n{'─' * 60}\n")
    log_fh.write(f"MODULE : {module_name}\n")
    log_fh.write(f"STATUS : {['PASS','FAIL','SKIP'][min(code,2)]}\n")
    if stdout:
        log_fh.write(f"STDOUT :\n{stdout}\n")
    if stderr:
        log_fh.write(f"STDERR :\n{stderr}\n")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Server hardening orchestrator")
    parser.add_argument("--modules",  nargs="+", metavar="SCRIPT",
                        help="Run specific module scripts only")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Discover modules but do not execute them")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable coloured output")
    args = parser.parse_args()

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False

    # Root check
    if os.geteuid() != 0 and not args.dry_run:
        print(red("ERROR: This script must be run as root (use sudo)."))
        sys.exit(1)

    ensure_dirs()
    print_banner()

    modules = discover_modules(args.modules)
    if not modules:
        print(yellow("WARNING: No modules found in"), MODULES_DIR)
        print(yellow("         Add your .sh scripts there and re-run."))
        sys.exit(0)

    print(f"  {dim('Modules dir :')} {MODULES_DIR}")
    print(f"  {dim('Log file    :')} {LOG_FILE}")
    print(f"  {dim('Modules     :')} {len(modules)} found")
    if args.dry_run:
        print(f"  {yellow('Mode        : DRY-RUN (no changes will be made)')}")
    print()

    # ── Run modules ───────────────────────────────────────────────────────────
    results = []   # list of (name, code)

    COL_W = 42     # width of the module name column

    print(f"  {'MODULE':<{COL_W}}  {'STATUS':<8}  NOTES")
    print(f"  {'─' * COL_W}  {'─' * 8}  {'─' * 28}")

    with open(LOG_FILE, "w") as log_fh:
        log_fh.write(f"Hardening run — {TIMESTAMP}\n")
        log_fh.write(f"Host: {os.uname().nodename}\n")

        for script in modules:
            name = os.path.basename(script)
            code, stdout, stderr = run_module(script, dry_run=args.dry_run)

            # Normalise exit code to 0/1/2
            if code not in (EXIT_PASS, EXIT_SKIP):
                code = EXIT_FAIL

            status = STATUS_LABEL.get(code, red("UNKN"))

            # Pull first output line as a short note (if available)
            note = stdout.splitlines()[0][:40] if stdout else ""

            print(f"  {name:<{COL_W}}  {status:<8}  {dim(note)}")
            log_write(log_fh, name, code, stdout, stderr)
            results.append((name, code))

        log_fh.write(f"\n{'─' * 60}\nDone.\n")

    # ── Summary ───────────────────────────────────────────────────────────────
    total = len(results)
    passed = sum(1 for _, c in results if c == EXIT_PASS)
    failed = sum(1 for _, c in results if c == EXIT_FAIL)
    skipped = sum(1 for _, c in results if c == EXIT_SKIP)
    score = int((passed / total * 100) if total else 0)

    print()
    print(bold("=" * 62))
    print(bold("  HARDENING SUMMARY"))
    print(bold("=" * 62))
    print(f"  {'Total modules':<20}  {total}")
    print(f"  {green('PASS'):<29}  {passed}")
    print(f"  {red('FAIL'):<29}  {failed}")
    print(f"  {yellow('SKIP'):<29}  {skipped}")
    print(f"  {'─' * 28}")

    score_str = f"{score}%"
    if score >= 80:
        score_display = green(score_str)
    elif score >= 50:
        score_display = yellow(score_str)
    else:
        score_display = red(score_str)

    print(f"  {'Hardening score':<20}  {score_display}")
    print()

    if failed:
        print(f"  {red('Failed modules:')}")
        for name, code in results:
            if code == EXIT_FAIL:
                print(f"    {red('✗')} {name}")
        print()

    print(f"  Full log saved to:")
    print(f"  {dim(LOG_FILE)}")
    print(bold("=" * 62))
    print()

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Start/stop a user-driven Playwright HAR capture without DevTools.

Setup (local to this skill; uses an existing Chromium installation):
    npm install --prefix "$SKILL_DIR/capture" --ignore-scripts

Start a capture and wait until its dedicated browser window is ready:
    python3 scripts/har_capture.py start \
      --workspace /path/to/DG06 --url http://lab.example.invalid/

After the user says the experiment is complete, gracefully close the context
and wait for HAR flush plus non-empty-content checks:
    python3 scripts/har_capture.py stop --workspace /path/to/DG06

This helper records a user's manual session only. It never replays requests,
submits forms, or performs dynamic judging verification. The HAR contains raw
credentials and request/response bodies; redact derived evidence before export.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.request

SKILL_DIR = Path(__file__).resolve().parent.parent
RECORDER = SKILL_DIR / "capture" / "har_recorder.mjs"
RUNTIME = SKILL_DIR / "capture" / "node_modules" / "playwright-core"


def read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot read JSON state {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"expected a JSON object in {path}")
    return value


def wait_for_phase(paths: dict[str, Path], phases: set[str], timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            state = read_json(paths["state"])
        except RuntimeError as exc:
            # Atomic state replacement can briefly race a reader.
            last_error = exc
        else:
            if state.get("phase") in phases:
                return state
            if state.get("phase") == "failed":
                raise RuntimeError(f"recorder failed: {state.get('error', 'unknown error')}")
        time.sleep(0.1)
    suffix = f"; last read error: {last_error}" if last_error else ""
    raise RuntimeError(f"timed out waiting for recorder state {sorted(phases)}{suffix}")


def har_summary(path: Path) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    document = read_json(path)
    log = document.get("log")
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise RuntimeError(f"{path} has no HAR log.entries array")
    embedded_bodies = 0
    post_requests = 0
    submit_candidates = 0
    build_artifact_candidates = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        content = response.get("content") if isinstance(response.get("content"), dict) else {}
        if isinstance(content.get("text"), str) and content["text"]:
            embedded_bodies += 1
        method = str(request.get("method", "")).upper()
        url = str(request.get("url", ""))
        if method == "POST":
            post_requests += 1
        if "sendjson" in url.lower():
            submit_candidates += 1
        lowered = url.lower().split("?", 1)[0]
        if (".wasm" in lowered or ".data" in lowered
                or lowered.endswith("global-metadata.dat")):
            build_artifact_candidates += 1
    return {
        "har": str(path),
        "sha256": digest.hexdigest(),
        "bytes": path.stat().st_size,
        "entries": len(entries),
        "responses_with_embedded_bodies": embedded_bodies,
        "post_requests": post_requests,
        "sendjson_candidates": submit_candidates,
        "build_artifact_candidates": build_artifact_candidates,
        "usable_capture": bool(entries) and embedded_bodies > 0,
    }


def paths_for(workspace: Path, name: str | None = None) -> dict[str, Path]:
    capture = workspace / "capture"
    raw = workspace / "raw"
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name or workspace.name).strip("-.")
    safe_name = safe_name or "session"
    return {
        "capture": capture,
        "raw": raw,
        "state": capture / "state.json",
        "stop": capture / "STOP",
        "log": capture / "recorder.log",
        "summary": capture / "har-summary.json",
        "har": raw / f"{safe_name}-{timestamp}.har",
    }


def require_runtime() -> None:
    if not RECORDER.is_file() or not RUNTIME.is_dir():
        raise RuntimeError(
            "Playwright runtime is not installed; run: "
            f"npm install --prefix {SKILL_DIR / 'capture'} --ignore-scripts"
        )


def pid_alive(pid: object) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def wait_for_recorder_exit(state: dict, timeout: float) -> None:
    """A stopped/failed recorder may still be flushing its HAR; do not overlap."""
    pid = state.get("pid")
    if not pid_alive(pid):
        return
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and pid_alive(pid):
        time.sleep(0.1)
    if pid_alive(pid):
        raise RuntimeError(f"previous recorder (pid {pid}) is still running; wait for it to exit or stop it")


CHROME_CANDIDATES = (
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
)


def find_browser(value: str) -> str:
    """Resolve a browser executable: explicit path/name or a common binary."""
    located = shutil.which(value)
    if located:
        return located
    if os.path.isfile(value):
        return value
    raise RuntimeError(f"browser executable not found: {value}")


def find_any_chrome() -> str:
    for name in CHROME_CANDIDATES:
        located = shutil.which(name)
        if located:
            return located
    raise RuntimeError(
        "no Chrome/Chromium binary found in PATH; pass --browser /path/to/chrome"
    )


def cdp_ready(port: int, timeout: float) -> bool:
    url = f"http://127.0.0.1:{port}/json/version"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.2)
    return False


def command_start_cdp(args: argparse.Namespace, workspace: Path, paths: dict[str, Path]) -> dict:
    """CDP mode: use the user's own Chrome window; recorder attaches passively.

    Chrome (M136+) ignores --remote-debugging-port on the default profile
    directory, so a separate --user-data-dir is mandatory for the port to
    work. That profile behaves like a normal Chrome profile (logins,
    extensions, sync) after its first sign-in.
    """
    if args.cdp_port <= 0:
        raise RuntimeError("--cdp-port must be positive")
    if args.browser:
        try:
            browser = find_browser(args.browser)
        except RuntimeError:
            if args.browser == "chromium":
                browser = find_any_chrome()
            else:
                raise
        profile_dir = (args.profile_dir or (workspace / "profiles" / "chrome-cdp")).resolve()
        profile_dir.mkdir(parents=True, exist_ok=True)
        launch = [
            browser,
            f"--remote-debugging-port={args.cdp_port}",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        # Do NOT pass --url to Chrome: it would load the page before the
        # recorder attaches and the initial navigation would be missed. The
        # recorder navigates after attaching instead.
        launch.append("about:blank")
        log = paths["log"].open("ab")
        try:
            process = subprocess.Popen(
                launch, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log.close()
        if not cdp_ready(args.cdp_port, args.ready_timeout):
            raise RuntimeError(
                f"launched {browser} but no CDP endpoint answered on port {args.cdp_port}; "
                "check capture/recorder.log"
            )
        browser_pid: int | None = process.pid
        browser_note = f"launched {browser} (pid {browser_pid}), profile {profile_dir}"
    else:
        if not cdp_ready(args.cdp_port, 3.0):
            raise RuntimeError(
                f"no CDP endpoint on port {args.cdp_port}; pass --browser to launch "
                "one, or start Chrome yourself with --remote-debugging-port"
            )
        browser_pid = None
        browser_note = f"attaching to running browser on port {args.cdp_port}"
    command = [
        "node", str(RECORDER), "--cdp", f"http://127.0.0.1:{args.cdp_port}",
        "--har", str(paths["har"]), "--state", str(paths["state"]),
        "--stop", str(paths["stop"]),
    ]
    if args.browser and args.url:
        command.extend(["--url", args.url])  # recorder navigates after attaching
    if args.headless:
        command.append("--headless")  # no-op in CDP mode; kept for symmetry
    log = paths["log"].open("ab")
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log.close()
    try:
        state = wait_for_phase(paths, {"ready"}, args.ready_timeout)
    except Exception:
        paths["stop"].touch()
        raise
    return {
        "status": "ready",
        "mode": "cdp-attach",
        "recorder_pid": process.pid,
        "browser_pid": browser_pid,
        "cdp_port": args.cdp_port,
        "har": state["har"],
        "state": str(paths["state"]),
        "browser": browser_note,
    }


def command_start(args: argparse.Namespace) -> int:
    require_runtime()
    workspace = args.workspace.resolve()
    paths = paths_for(workspace, args.name)
    paths["capture"].mkdir(parents=True, exist_ok=True)
    paths["raw"].mkdir(parents=True, exist_ok=True)
    if paths["state"].is_file():
        try:
            previous = read_json(paths["state"])
        except RuntimeError:
            previous = {}
        wait_for_recorder_exit(previous, args.ready_timeout)
    if paths["stop"].exists():
        paths["stop"].unlink()
    if args.cdp:
        result = command_start_cdp(args, workspace, paths)
        print(json.dumps(result, ensure_ascii=False))
        print("CAPTURE READY (CDP attach); the window is the user's own browser; "
              "stopping the capture will NOT close it")
        return 0
    command = [
        "node", str(RECORDER), "--url", args.url, "--browser", args.browser,
        "--har", str(paths["har"]), "--state", str(paths["state"]),
        "--stop", str(paths["stop"]),
    ]
    if args.headless:
        command.append("--headless")
    log = paths["log"].open("wb")
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log.close()
    try:
        state = wait_for_phase(paths, {"ready"}, args.ready_timeout)
    except Exception:
        paths["stop"].touch()
        raise
    result = {"status": "ready", "pid": process.pid, "har": state["har"], "state": str(paths["state"])}
    print(json.dumps(result, ensure_ascii=False))
    print("CAPTURE READY; user may now perform the experiment manually")
    return 0


def command_stop(args: argparse.Namespace) -> int:
    paths = paths_for(args.workspace.resolve())
    state = read_json(paths["state"])
    if state.get("phase") not in {"stopped", "failed"}:
        paths["stop"].touch()
        state = wait_for_phase(paths, {"stopped", "failed"}, args.stop_timeout)
    har = Path(state["har"])
    if not har.is_file():
        raise RuntimeError(f"recorder stopped without producing a HAR: {har}")
    summary = har_summary(har)
    paths["summary"].write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    if not summary["usable_capture"]:
        print("CAPTURE EMPTY OR MISSING BODIES; do not claim that analysis can start")
        return 1
    print("CAPTURE COMPLETE; run intake next")
    return 0


def command_status(args: argparse.Namespace) -> int:
    paths = paths_for(args.workspace.resolve())
    state = read_json(paths["state"])
    print(json.dumps(state, ensure_ascii=False))
    har = Path(state["har"])
    if state.get("phase") == "stopped" and har.is_file():
        print(json.dumps(har_summary(har), ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("start", help="launch a dedicated capture window")
    start.add_argument("--workspace", type=Path, required=True)
    start.add_argument("--url", required=True)
    start.add_argument("--name", help="HAR filename prefix; defaults to workspace name")
    start.add_argument("--browser", default="chromium", help="Chromium executable path/name")
    start.add_argument("--headless", action="store_true", help="testing only; no visible window")
    start.add_argument("--cdp", action="store_true",
                       help="attach to the user's own Chrome over CDP instead of a "
                            "dedicated window; the browser is not closed on stop")
    start.add_argument("--cdp-port", type=int, default=9222,
                       help="CDP port for --cdp mode (default 9222)")
    start.add_argument("--profile-dir", type=Path, default=None,
                       help="user-data-dir for the launched Chrome in --cdp mode "
                            "(default <workspace>/profiles/chrome-cdp)")
    start.add_argument("--ready-timeout", type=float, default=45.0)
    start.set_defaults(handler=command_start)
    stop = subparsers.add_parser("stop", help="gracefully stop and validate the HAR")
    stop.add_argument("--workspace", type=Path, required=True)
    stop.add_argument("--stop-timeout", type=float, default=60.0)
    stop.set_defaults(handler=command_stop)
    status = subparsers.add_parser("status", help="show recorder state and capture counts")
    status.add_argument("--workspace", type=Path, required=True)
    status.set_defaults(handler=command_status)
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"CAPTURE ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

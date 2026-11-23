import logging
import os
import queue
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Set

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

USERS_ROOT = Path(os.environ.get("USERS_ROOT", "/srv/app/users")).resolve()
# Path of USERS_ROOT as seen by the *host* docker daemon (bind-mount sources are resolved on the host).
HOST_USERS_ROOT = os.environ.get("HOST_USERS_ROOT", str(USERS_ROOT)).rstrip("/")
DOCKER_IMAGE = os.environ.get("CICFLOWMETER_IMAGE", "cicflowmeter-worker:latest")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "3.0"))
# Number of conversions that may run in parallel.
PCAP_WORKERS = max(1, int(os.environ.get("PCAP_WORKERS", "1")))
# How many times a pcap may fail the stability check (empty / still growing) before it is quarantined.
MAX_UNSTABLE_ATTEMPTS = int(os.environ.get("MAX_UNSTABLE_ATTEMPTS", "5"))
# Delay before retrying a pcap after an infrastructure error (docker unavailable, image missing, ...).
INFRA_RETRY_DELAY = float(os.environ.get("INFRA_RETRY_DELAY", "60"))
# Leftover staging dirs older than this (seconds) are removed at startup.
STAGING_MAX_AGE = float(os.environ.get("STAGING_MAX_AGE", "3600"))
# Worker container limits. A conversion that runs longer than WORKER_TIMEOUT seconds is killed.
WORKER_TIMEOUT = float(os.environ.get("WORKER_TIMEOUT", "1800"))
WORKER_MEMORY = os.environ.get("WORKER_MEMORY", "2g")
WORKER_CPUS = os.environ.get("WORKER_CPUS", "1")
# Optional "uid:gid" to run the worker as. Empty = the image default (root, with all capabilities
# dropped except DAC_OVERRIDE so it can read uploaded pcaps regardless of their owner).
WORKER_USER = os.environ.get("WORKER_USER", "").strip()

STAGING_DIR_NAME = ".staging"
FAILED_DIR_NAME = "failed"
FLOW_SUFFIX = "_Flow.csv"  # CICFlowMeter writes <pcap file name>_Flow.csv (FlowMgr.FLOW_SUFFIX)
# `docker run` exit codes that mean docker itself failed, not the pcap conversion.
DOCKER_INFRA_EXIT_CODES = {125, 126, 127}
CONTAINER_PCAP_DIR = "/in"
CONTAINER_OUT_DIR = "/out"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s %(message)s",
)
log = logging.getLogger("pcap-watcher")

stop_event = threading.Event()


def wait_until_file_stable(path: Path, checks: int = 3, delay: float = 0.5) -> bool:
    """Wait until file size stops changing so in-flight uploads finish first."""
    prev_size = -1
    stable_count = 0
    for _ in range(60):
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return False
        if size > 0 and size == prev_size:
            stable_count += 1
            if stable_count >= checks:
                return True
        else:
            stable_count = 0
            prev_size = size
        time.sleep(delay)
    return False


def parse_pcap_path(pcap_path: Path) -> Optional[tuple[str, str, Path]]:
    """
    Expects: <USERS_ROOT>/<user_id>/comp/<computer_id>/pcaps/<file>.pcap
    Returns: (user_id, computer_id, csv_dir) or None if path does not match.
    """
    try:
        rel = pcap_path.resolve().relative_to(USERS_ROOT)
    except ValueError:
        return None

    if len(rel.parts) != 5:
        return None
    user_id, comp_literal, computer_id, folder_name, filename = rel.parts
    if comp_literal != "comp" or folder_name != "pcaps":
        return None
    if not filename.lower().endswith(".pcap"):
        return None

    csv_dir = USERS_ROOT / user_id / "comp" / computer_id / "csvs"
    return user_id, computer_id, csv_dir


def unique_destination(directory: Path, name: str) -> Path:
    """Return directory/name, or a timestamped variant if that file already exists."""
    dest = directory / name
    if dest.exists():
        dest = directory / f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}_{name}"
    return dest


def quarantine_pcap(pcap_path: Path, reason: str, details: str = "") -> None:
    """Move a pcap that cannot be converted into pcaps/failed/ with a .log next to it,
    so the rescan loop does not keep retrying it (failed/ is too deep for parse_pcap_path)."""
    failed_dir = pcap_path.parent / FAILED_DIR_NAME
    failed_dir.mkdir(parents=True, exist_ok=True)
    dest = unique_destination(failed_dir, pcap_path.name)
    try:
        os.replace(pcap_path, dest)
    except FileNotFoundError:
        return
    dest.with_name(dest.name + ".log").write_text(
        f"time: {time.strftime('%Y-%m-%d %H:%M:%S')}\nreason: {reason}\n\n{details}\n",
        encoding="utf-8",
    )
    log.error("Quarantined %s -> %s (%s)", pcap_path, dest, reason)


def cleanup_stale_staging() -> None:
    """Remove staging dirs left behind by a crash or kill."""
    now = time.time()
    for staging in USERS_ROOT.glob(f"*/comp/*/{STAGING_DIR_NAME}/*"):
        try:
            if staging.is_dir() and now - staging.stat().st_mtime > STAGING_MAX_AGE:
                shutil.rmtree(staging, ignore_errors=True)
                log.info("Removed stale staging dir %s", staging)
        except OSError:
            pass


def mount_arg(src: str, dst: str, readonly: bool) -> str:
    """Build a --mount value. Docker parses it as CSV, so quote fields to allow ',' in paths."""
    fields = ["type=bind", f"src={src}", f"dst={dst}"]
    if readonly:
        fields.append("readonly")
    return ",".join('"' + f.replace('"', '""') + '"' for f in fields)


def host_path(*parts: str) -> str:
    """Path under HOST_USERS_ROOT as the host docker daemon sees it (always POSIX)."""
    return "/".join([HOST_USERS_ROOT, *parts])


def build_worker_cmd(container_name: str, user_id: str, computer_id: str, pcap_name: str, job_id: str) -> List[str]:
    """The worker only gets the pcaps/ dir (read-only) and its own staging dir, no network,
    a read-only root filesystem, no capabilities beyond reading files, and resource limits."""
    cmd = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--platform", "linux/amd64",
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=256m",
        "--security-opt", "no-new-privileges",
        "--cap-drop", "ALL",
        "--cap-add", "DAC_OVERRIDE",
        "--pids-limit", "256",
        "--memory", WORKER_MEMORY,
        "--cpus", WORKER_CPUS,
        "--mount", mount_arg(host_path(user_id, "comp", computer_id, "pcaps"), CONTAINER_PCAP_DIR, True),
        "--mount", mount_arg(
            host_path(user_id, "comp", computer_id, STAGING_DIR_NAME, job_id), CONTAINER_OUT_DIR, False
        ),
    ]
    if WORKER_USER:
        cmd += ["--user", WORKER_USER]
    cmd += [DOCKER_IMAGE, f"{CONTAINER_PCAP_DIR}/{pcap_name}", CONTAINER_OUT_DIR]
    return cmd


def force_remove_container(name: str) -> None:
    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.error("Could not remove worker container %s: %s", name, exc)


class PcapProcessor:
    """Paths are submitted from the observer thread and the rescan loop; a fixed pool of
    worker threads processes them. `pending` dedupes so a file is queued/processed once."""

    def __init__(self) -> None:
        self.queue: "queue.Queue[Path]" = queue.Queue()
        self.lock = threading.Lock()
        self.pending: Set[Path] = set()
        self.unstable_attempts: Dict[Path, int] = {}
        self.retry_after: Dict[Path, float] = {}

    def submit(self, raw_path: Path) -> None:
        try:
            pcap_path = raw_path.resolve()
        except OSError:
            return
        if parse_pcap_path(pcap_path) is None:
            return
        with self.lock:
            if pcap_path in self.pending:
                return
            if time.monotonic() < self.retry_after.get(pcap_path, 0.0):
                return
            self.pending.add(pcap_path)
        self.queue.put(pcap_path)

    def worker_loop(self) -> None:
        while not stop_event.is_set():
            try:
                pcap_path = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self.handle_file(pcap_path)
            except Exception:
                log.exception("Unexpected error while processing %s", pcap_path)
            finally:
                with self.lock:
                    self.pending.discard(pcap_path)
                self.queue.task_done()

    def _set_retry(self, pcap_path: Path, delay: float) -> None:
        with self.lock:
            self.retry_after[pcap_path] = time.monotonic() + delay

    def handle_file(self, pcap_path: Path) -> None:
        if stop_event.is_set() or not pcap_path.exists():
            return
        parsed = parse_pcap_path(pcap_path)
        if not parsed:
            return
        user_id, computer_id, csv_dir = parsed

        if not wait_until_file_stable(pcap_path):
            if not pcap_path.exists():
                return
            attempts = self.unstable_attempts.get(pcap_path, 0) + 1
            self.unstable_attempts[pcap_path] = attempts
            if attempts >= MAX_UNSTABLE_ATTEMPTS:
                self.unstable_attempts.pop(pcap_path, None)
                quarantine_pcap(pcap_path, f"empty or still changing after {attempts} stability checks")
            else:
                log.warning("PCAP not stable yet (attempt %s/%s): %s", attempts, MAX_UNSTABLE_ATTEMPTS, pcap_path)
            return
        self.unstable_attempts.pop(pcap_path, None)

        # CICFlowMeter appends rows to its CSV while it runs, so it writes into a private
        # staging dir; the finished CSV is then moved into csvs/ in one atomic rename and
        # the CSV watcher never sees a partially written file. Staging must be on the same
        # filesystem as csvs/ for os.replace to be atomic, hence it lives next to it.
        job_id = uuid.uuid4().hex
        staging_dir = USERS_ROOT / user_id / "comp" / computer_id / STAGING_DIR_NAME / job_id
        try:
            staging_dir.mkdir(parents=True, exist_ok=True)
            if WORKER_USER:
                uid, _, gid = WORKER_USER.partition(":")
                os.chown(staging_dir, int(uid), int(gid or uid))
            csv_dir.mkdir(parents=True, exist_ok=True)
            self._convert(pcap_path, user_id, computer_id, csv_dir, staging_dir, job_id)
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)

    def _convert(
        self, pcap_path: Path, user_id: str, computer_id: str, csv_dir: Path, staging_dir: Path, job_id: str
    ) -> None:
        container_name = f"cfm-{job_id[:12]}"
        cmd = build_worker_cmd(container_name, user_id, computer_id, pcap_path.name, job_id)

        log.info("Running CICFlowMeter for user=%s comp=%s file=%s", user_id, computer_id, pcap_path.name)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=WORKER_TIMEOUT)
        except subprocess.TimeoutExpired as exc:
            force_remove_container(container_name)
            quarantine_pcap(
                pcap_path,
                f"CICFlowMeter timed out after {WORKER_TIMEOUT:.0f}s",
                f"STDOUT:\n{exc.stdout or ''}\n\nSTDERR:\n{exc.stderr or ''}",
            )
            return
        except OSError as exc:  # docker CLI missing / not executable
            log.error("Could not run docker for %s: %s; retrying in %ss", pcap_path, exc, INFRA_RETRY_DELAY)
            self._set_retry(pcap_path, INFRA_RETRY_DELAY)
            return

        output = f"exit code: {result.returncode}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"

        if result.returncode in DOCKER_INFRA_EXIT_CODES:
            # Docker itself failed (daemon unreachable, image missing, ...): not the pcap's fault.
            log.error(
                "docker run failed (exit=%s) for %s; keeping PCAP, retrying in %ss\nSTDERR: %s",
                result.returncode, pcap_path, INFRA_RETRY_DELAY, result.stderr.strip(),
            )
            self._set_retry(pcap_path, INFRA_RETRY_DELAY)
            return
        with self.lock:
            self.retry_after.pop(pcap_path, None)

        if result.returncode != 0:
            reason = f"CICFlowMeter exited with {result.returncode}"
            if result.returncode == 137:
                reason += f" (killed - likely out of memory, WORKER_MEMORY={WORKER_MEMORY})"
            quarantine_pcap(pcap_path, reason, output)
            return

        # Only the exact file this run produced counts (Cmd.java: <out>/<pcap name>_Flow.csv).
        produced = staging_dir / f"{pcap_path.name}{FLOW_SUFFIX}"
        if not produced.is_file() or produced.stat().st_size == 0:
            quarantine_pcap(pcap_path, f"CICFlowMeter produced no CSV ({produced.name})", output)
            return

        final_csv = csv_dir / produced.name
        os.replace(produced, final_csv)
        pcap_path.unlink()
        log.info("Generated %s and deleted PCAP: %s", final_csv, pcap_path)


class PcapEventHandler(FileSystemEventHandler):
    def __init__(self, processor: PcapProcessor) -> None:
        self.processor = processor

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.processor.submit(Path(event.src_path))

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self.processor.submit(Path(event.dest_path))


def scan_existing(processor: PcapProcessor) -> None:
    for pcap_file in USERS_ROOT.glob("*/comp/*/pcaps/*.pcap"):
        processor.submit(pcap_file)


def _handle_stop_signal(signum, _frame) -> None:
    log.info("Received signal %s, finishing current work and stopping...", signum)
    stop_event.set()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    USERS_ROOT.mkdir(parents=True, exist_ok=True)
    cleanup_stale_staging()
    processor = PcapProcessor()

    workers = [
        threading.Thread(target=processor.worker_loop, name=f"worker-{i}", daemon=True)
        for i in range(PCAP_WORKERS)
    ]
    for t in workers:
        t.start()

    observer = Observer()
    observer.schedule(PcapEventHandler(processor), str(USERS_ROOT), recursive=True)
    observer.start()
    log.info(
        "Watching PCAPs under %s (mount source: %s, workers: %s)", USERS_ROOT, HOST_USERS_ROOT, PCAP_WORKERS
    )

    exit_code = 0
    try:
        while not stop_event.is_set():
            try:
                scan_existing(processor)
            except OSError:
                log.exception("Rescan failed")
            if not observer.is_alive():
                log.error("File observer died; exiting so the container restarts")
                exit_code = 1
                break
            stop_event.wait(POLL_INTERVAL)
    finally:
        stop_event.set()
        observer.stop()
        observer.join(timeout=10)
        # Let the job that is currently running finish (bounded by compose stop_grace_period).
        for t in workers:
            t.join()
        log.info("PCAP watcher stopped.")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()

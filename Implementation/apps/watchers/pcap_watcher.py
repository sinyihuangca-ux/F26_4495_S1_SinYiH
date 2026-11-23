import logging
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Dict, Optional, Set

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

USERS_ROOT = Path(os.environ.get("USERS_ROOT", "/srv/app/users")).resolve()
HOST_USERS_ROOT = os.environ.get("HOST_USERS_ROOT", str(USERS_ROOT))
DOCKER_IMAGE = os.environ.get("CICFLOWMETER_IMAGE", "cicflowmeter-worker:latest")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "3.0"))
# How many times a pcap may fail the stability check (empty / still growing) before it is quarantined.
MAX_UNSTABLE_ATTEMPTS = int(os.environ.get("MAX_UNSTABLE_ATTEMPTS", "5"))
# Delay before retrying a pcap after an infrastructure error (docker unavailable, image missing, ...).
INFRA_RETRY_DELAY = float(os.environ.get("INFRA_RETRY_DELAY", "60"))
# Leftover staging dirs older than this (seconds) are removed at startup.
STAGING_MAX_AGE = float(os.environ.get("STAGING_MAX_AGE", "3600"))

STAGING_DIR_NAME = ".staging"
FAILED_DIR_NAME = "failed"
FLOW_SUFFIX = "_Flow.csv"  # CICFlowMeter writes <pcap file name>_Flow.csv (FlowMgr.FLOW_SUFFIX)
# `docker run` exit codes that mean docker itself failed, not the pcap conversion.
DOCKER_INFRA_EXIT_CODES = {125, 126, 127}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("pcap-watcher")


def wait_until_file_stable(path: Path, checks: int = 3, delay: float = 0.5) -> bool:
    """Wait until file size stops changing so in-flight uploads finish first."""
    prev_size = -1
    stable_count = 0
    for _ in range(60):
        if not path.exists():
            return False
        size = path.stat().st_size
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


class PcapProcessor:
    def __init__(self) -> None:
        self.in_flight: Set[Path] = set()
        self.unstable_attempts: Dict[Path, int] = {}
        self.retry_after: Dict[Path, float] = {}

    def handle_file(self, raw_path: Path) -> None:
        pcap_path = raw_path.resolve()
        if pcap_path in self.in_flight or not pcap_path.exists():
            return
        if time.monotonic() < self.retry_after.get(pcap_path, 0.0):
            return

        parsed = parse_pcap_path(pcap_path)
        if not parsed:
            return

        user_id, computer_id, csv_dir = parsed
        self.in_flight.add(pcap_path)
        staging_dir: Optional[Path] = None
        try:
            if not wait_until_file_stable(pcap_path):
                attempts = self.unstable_attempts.get(pcap_path, 0) + 1
                self.unstable_attempts[pcap_path] = attempts
                if attempts >= MAX_UNSTABLE_ATTEMPTS:
                    self.unstable_attempts.pop(pcap_path, None)
                    quarantine_pcap(pcap_path, f"empty or still changing after {attempts} stability checks")
                else:
                    log.warning(
                        "PCAP not stable yet (attempt %s/%s): %s", attempts, MAX_UNSTABLE_ATTEMPTS, pcap_path
                    )
                return
            self.unstable_attempts.pop(pcap_path, None)

            # CICFlowMeter appends rows to its CSV while it runs, so it writes into a private
            # staging dir; the finished CSV is then moved into csvs/ in one atomic rename and
            # the CSV watcher never sees a partially written file. Staging must be on the same
            # filesystem as csvs/ for os.replace to be atomic, hence it lives next to it.
            job_id = uuid.uuid4().hex
            staging_dir = USERS_ROOT / user_id / "comp" / computer_id / STAGING_DIR_NAME / job_id
            staging_dir.mkdir(parents=True, exist_ok=True)
            csv_dir.mkdir(parents=True, exist_ok=True)

            container_pcap = f"/data/users/{user_id}/comp/{computer_id}/pcaps/{pcap_path.name}"
            container_out_dir = f"/data/users/{user_id}/comp/{computer_id}/{STAGING_DIR_NAME}/{job_id}"

            cmd = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{HOST_USERS_ROOT}:/data/users",
                DOCKER_IMAGE,
                container_pcap,
                container_out_dir,
            ]

            log.info("Running CICFlowMeter for user=%s comp=%s file=%s", user_id, computer_id, pcap_path.name)
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
            except OSError as exc:  # docker CLI missing / not executable
                log.error("Could not run docker for %s: %s; retrying in %ss", pcap_path, exc, INFRA_RETRY_DELAY)
                self.retry_after[pcap_path] = time.monotonic() + INFRA_RETRY_DELAY
                return

            output = f"exit code: {result.returncode}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"

            if result.returncode in DOCKER_INFRA_EXIT_CODES:
                # Docker itself failed (daemon unreachable, image missing, ...): not the pcap's fault.
                log.error(
                    "docker run failed (exit=%s) for %s; keeping PCAP, retrying in %ss\nSTDERR: %s",
                    result.returncode,
                    pcap_path,
                    INFRA_RETRY_DELAY,
                    result.stderr.strip(),
                )
                self.retry_after[pcap_path] = time.monotonic() + INFRA_RETRY_DELAY
                return
            self.retry_after.pop(pcap_path, None)

            if result.returncode != 0:
                quarantine_pcap(pcap_path, f"CICFlowMeter exited with {result.returncode}", output)
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
        finally:
            if staging_dir is not None:
                shutil.rmtree(staging_dir, ignore_errors=True)
            self.in_flight.discard(pcap_path)


class PcapEventHandler(FileSystemEventHandler):
    def __init__(self, processor: PcapProcessor) -> None:
        self.processor = processor

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.processor.handle_file(Path(event.src_path))

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self.processor.handle_file(Path(event.dest_path))


def scan_existing(processor: PcapProcessor) -> None:
    for pcap_file in USERS_ROOT.glob("*/comp/*/pcaps/*.pcap"):
        processor.handle_file(pcap_file)


def main() -> None:
    USERS_ROOT.mkdir(parents=True, exist_ok=True)
    cleanup_stale_staging()
    processor = PcapProcessor()
    scan_existing(processor)

    observer = Observer()
    observer.schedule(PcapEventHandler(processor), str(USERS_ROOT), recursive=True)
    observer.start()
    log.info("Watching PCAPs under %s (mount source: %s)", USERS_ROOT, HOST_USERS_ROOT)

    try:
        while True:
            time.sleep(POLL_INTERVAL)
            scan_existing(processor)
    except KeyboardInterrupt:
        log.info("Stopping PCAP watcher...")
    finally:
        observer.stop()
        observer.join()


if __name__ == "__main__":
    main()
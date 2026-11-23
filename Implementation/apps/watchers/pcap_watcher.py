import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional, Set

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

USERS_ROOT = Path(os.environ.get("USERS_ROOT", "/srv/app/users")).resolve()
HOST_USERS_ROOT = os.environ.get("HOST_USERS_ROOT", str(USERS_ROOT))
DOCKER_IMAGE = os.environ.get("CICFLOWMETER_IMAGE", "cicflowmeter-worker:latest")
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "3.0"))

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


class PcapProcessor:
    def __init__(self) -> None:
        self.in_flight: Set[Path] = set()

    def handle_file(self, raw_path: Path) -> None:
        pcap_path = raw_path.resolve()
        if pcap_path in self.in_flight or not pcap_path.exists():
            return

        parsed = parse_pcap_path(pcap_path)
        if not parsed:
            return

        user_id, computer_id, csv_dir = parsed
        self.in_flight.add(pcap_path)
        try:
            if not wait_until_file_stable(pcap_path):
                log.warning("Skipping unstable or empty pcap: %s", pcap_path)
                return

            csv_dir.mkdir(parents=True, exist_ok=True)
            before_csvs = {p.name: p.stat().st_mtime_ns for p in csv_dir.glob("*.csv")}

            container_pcap = f"/data/users/{user_id}/comp/{computer_id}/pcaps/{pcap_path.name}"
            container_csv_dir = f"/data/users/{user_id}/comp/{computer_id}/csvs"

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
                container_csv_dir,
            ]

            log.info("Running CICFlowMeter for user=%s comp=%s file=%s", user_id, computer_id, pcap_path.name)
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                log.error(
                    "CICFlowMeter failed (exit=%s) for %s\nSTDOUT: %s\nSTDERR: %s",
                    result.returncode,
                    pcap_path,
                    result.stdout.strip(),
                    result.stderr.strip(),
                )
                return

            created_or_updated = [
                p for p in csv_dir.glob("*.csv")
                if p.stat().st_size > 0 and (
                    p.name not in before_csvs or p.stat().st_mtime_ns >= before_csvs[p.name]
                )
            ]
            if not created_or_updated:
                log.error("No non-empty CSV produced for %s; keeping PCAP for safety.", pcap_path)
                return

            pcap_path.unlink()
            log.info(
                "Generated %s and deleted PCAP: %s",
                ", ".join(p.name for p in created_or_updated),
                pcap_path,
            )
        finally:
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
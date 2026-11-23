import logging
import os
import queue
import signal
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

USERS_ROOT = Path(os.environ.get("USERS_ROOT", "/srv/app/users")).resolve()
INFERENCE_URL = os.environ.get("INFERENCE_URL", "http://127.0.0.1:8000/predict")
INFERENCE_TIMEOUT = float(os.environ.get("INFERENCE_TIMEOUT", "120"))
POLL_INTERVAL = float(os.environ.get("POLL_INTERVAL", "3.0"))
# After a successful send the CSV is moved to csvs/processed/ (default) or deleted.
DELETE_AFTER_SEND = os.environ.get("DELETE_AFTER_SEND", "false").lower() in ("1", "true", "yes")
# Failed sends are retried with exponential backoff, then moved to csvs/failed/.
MAX_SEND_ATTEMPTS = int(os.environ.get("MAX_SEND_ATTEMPTS", "8"))
RETRY_BASE_DELAY = float(os.environ.get("RETRY_BASE_DELAY", "5"))
RETRY_MAX_DELAY = float(os.environ.get("RETRY_MAX_DELAY", "600"))

PROCESSED_DIR_NAME = "processed"
FAILED_DIR_NAME = "failed"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("csv-inference-watcher")

stop_event = threading.Event()


def unique_destination(directory: Path, name: str) -> Path:
    """Return directory/name, or a timestamped variant if that file already exists."""
    dest = directory / name
    if dest.exists():
        dest = directory / f"{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}_{name}"
    return dest


def move_into(csv_path: Path, dir_name: str) -> Path:
    """Move csv into csvs/<dir_name>/. Those subdirs are too deep for parse_csv_path and the
    scan glob, so a moved file is never picked up again; this replaces a processed-state file."""
    target_dir = csv_path.parent / dir_name
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = unique_destination(target_dir, csv_path.name)
    os.replace(csv_path, dest)
    return dest


def wait_until_csv_ready(path: Path, checks: int = 3, delay: float = 0.4) -> bool:
    prev_size = -1
    stable_count = 0
    for _ in range(60):
        if not path.exists():
            return False
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


def parse_csv_path(csv_path: Path) -> Optional[tuple[str, str]]:
    """
    Expects: <USERS_ROOT>/<user_id>/comp/<computer_id>/csvs/<file>.csv
    Returns: (user_id, computer_id) or None if path does not match.
    """
    try:
        rel = csv_path.resolve().relative_to(USERS_ROOT)
    except ValueError:
        return None

    if len(rel.parts) != 5:
        return None
    user_id, comp_literal, computer_id, folder_name, filename = rel.parts
    if comp_literal != "comp" or folder_name != "csvs":
        return None
    if not filename.lower().endswith(".csv"):
        return None

    return user_id, computer_id


def send_csv_to_inference(csv_path: Path, user_id: str, computer_id: str) -> bool:
    """Send multipart/form-data request with CSV file and user/computer metadata."""
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    file_bytes = csv_path.read_bytes()

    body = bytearray()

    def add_field(name: str, value: str) -> None:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        body.extend(f"{value}\r\n".encode("utf-8"))

    add_field("user_id", user_id)
    add_field("computer_id", computer_id)

    body.extend(f"--{boundary}\r\n".encode("utf-8"))
    body.extend(
        f'Content-Disposition: form-data; name="file"; filename="{csv_path.name}"\r\n'.encode("utf-8")
    )
    body.extend(b"Content-Type: text/csv\r\n\r\n")
    body.extend(file_bytes)
    body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(
        INFERENCE_URL,
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=INFERENCE_TIMEOUT) as resp:
            status = resp.getcode()
            resp_body = resp.read().decode("utf-8", errors="replace")
            if 200 <= status < 300:
                log.info(
                    "Inference succeeded (status=%s) user=%s comp=%s csv=%s response=%s",
                    status,
                    user_id,
                    computer_id,
                    csv_path.name,
                    resp_body[:300],
                )
                return True
            log.error("Inference returned status %s for %s", status, csv_path)
            return False
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300] if exc.fp else ""
        log.error("Inference returned status %s for %s: %s", exc.code, csv_path, body)
        return False
    except (urllib.error.URLError, OSError) as exc:  # OSError covers timeouts and connection resets
        log.error("Failed to reach inference engine at %s for %s: %s", INFERENCE_URL, csv_path, exc)
        return False


class CsvProcessor:
    def __init__(self) -> None:
        self.queue: "queue.Queue[Path]" = queue.Queue()
        self.lock = threading.Lock()
        # Paths queued or being sent; dedupes events from the observer and the rescan.
        self.in_flight: Set[str] = set()
        # path -> (failed attempts so far, monotonic time before which we do not retry)
        self.failures: Dict[str, Tuple[int, float]] = {}

    def _record_failure(self, csv_path: Path, key: str, reason: str) -> None:
        with self.lock:
            attempts = self.failures.get(key, (0, 0.0))[0] + 1
            give_up = attempts >= MAX_SEND_ATTEMPTS
            delay = min(RETRY_BASE_DELAY * (2 ** (attempts - 1)), RETRY_MAX_DELAY)
            if give_up:
                self.failures.pop(key, None)
            else:
                self.failures[key] = (attempts, time.monotonic() + delay)
        if give_up:
            try:
                dest = move_into(csv_path, FAILED_DIR_NAME)
                log.error("Giving up on %s after %s attempts (%s); moved to %s", csv_path, attempts, reason, dest)
            except FileNotFoundError:
                pass
            return
        log.warning(
            "%s for %s (attempt %s/%s); retrying in %.0fs", reason, csv_path, attempts, MAX_SEND_ATTEMPTS, delay
        )

    def submit(self, raw_path: Path) -> None:
        """Called from the observer thread and the rescan loop; only the worker thread sends."""
        try:
            csv_path = raw_path.resolve()
        except OSError:
            return
        if parse_csv_path(csv_path) is None:
            return
        key = str(csv_path)
        with self.lock:
            if key in self.in_flight:
                return
            if time.monotonic() < self.failures.get(key, (0, 0.0))[1]:
                return
            self.in_flight.add(key)
        self.queue.put(csv_path)

    def worker_loop(self) -> None:
        while not stop_event.is_set():
            try:
                csv_path = self.queue.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self.handle_file(csv_path)
            except Exception:
                log.exception("Unexpected error while processing %s", csv_path)
            finally:
                with self.lock:
                    self.in_flight.discard(str(csv_path))
                self.queue.task_done()

    def handle_file(self, csv_path: Path) -> None:
        key = str(csv_path)
        if stop_event.is_set() or not csv_path.exists():
            return
        parsed = parse_csv_path(csv_path)
        if not parsed:
            return

        user_id, computer_id = parsed
        # pcap-watcher moves finished CSVs in atomically; this is a safety net for CSVs
        # copied into csvs/ by other means.
        if not wait_until_csv_ready(csv_path):
            if csv_path.exists():
                self._record_failure(csv_path, key, "CSV empty or still changing")
            return

        log.info("Sending CSV to inference engine: user=%s comp=%s file=%s", user_id, computer_id, csv_path.name)
        try:
            ok = send_csv_to_inference(csv_path, user_id, computer_id)
        except FileNotFoundError:
            return  # removed while we were working on it
        if not ok:
            self._record_failure(csv_path, key, "Inference request failed")
            return

        with self.lock:
            self.failures.pop(key, None)
        try:
            if DELETE_AFTER_SEND:
                csv_path.unlink()
                log.info("Deleted sent CSV %s", csv_path)
            else:
                dest = move_into(csv_path, PROCESSED_DIR_NAME)
                log.info("Archived sent CSV to %s", dest)
        except FileNotFoundError:
            pass


class CsvEventHandler(FileSystemEventHandler):
    def __init__(self, processor: CsvProcessor) -> None:
        self.processor = processor

    def on_created(self, event) -> None:
        if not event.is_directory:
            self.processor.submit(Path(event.src_path))

    def on_moved(self, event) -> None:
        if not event.is_directory:
            self.processor.submit(Path(event.dest_path))


def scan_existing(processor: CsvProcessor) -> None:
    for csv_file in USERS_ROOT.glob("*/comp/*/csvs/*.csv"):
        processor.submit(csv_file)


def _handle_stop_signal(signum, _frame) -> None:
    log.info("Received signal %s, finishing current send and stopping...", signum)
    stop_event.set()


def main() -> None:
    signal.signal(signal.SIGTERM, _handle_stop_signal)
    signal.signal(signal.SIGINT, _handle_stop_signal)

    USERS_ROOT.mkdir(parents=True, exist_ok=True)
    processor = CsvProcessor()
    worker = threading.Thread(target=processor.worker_loop, name="sender", daemon=True)
    worker.start()

    observer = Observer()
    observer.schedule(CsvEventHandler(processor), str(USERS_ROOT), recursive=True)
    observer.start()
    log.info("Watching CSVs under %s -> %s", USERS_ROOT, INFERENCE_URL)

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
        worker.join(timeout=INFERENCE_TIMEOUT + 10)
        log.info("CSV inference watcher stopped.")
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
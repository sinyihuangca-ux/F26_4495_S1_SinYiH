"""Mock ML inference engine for testing csv_inference_watcher.

POST /predict  multipart/form-data: user_id, computer_id, file (CSV)
GET  /control?mode=ok|fail|slow|down   switch behaviour for failure tests
Every request is appended to requests.jsonl with a validation report.
"""
import io, json, sys, time
from email.parser import BytesParser
from email.policy import HTTP
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import numpy as np
import pandas as pd

LOG = sys.argv[1] if len(sys.argv) > 1 else "requests.jsonl"
STATE = {"mode": "ok"}
EXPECTED_COLS = 84  # CICFlowMeter 4.0 output incl. Label
ID_COLS = ["Flow ID", "Src IP", "Src Port", "Dst IP", "Timestamp", "Label"]


def parse_multipart(headers, body):
    msg = BytesParser(policy=HTTP).parsebytes(
        b"Content-Type: " + headers["Content-Type"].encode() + b"\r\n\r\n" + body
    )
    fields, files = {}, {}
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        fname = part.get_filename()
        data = part.get_payload(decode=True)
        if fname:
            files[name] = (fname, data)
        else:
            fields[name] = data.decode()
    return fields, files


def validate(csv_bytes):
    rep = {}
    df = pd.read_csv(io.BytesIO(csv_bytes))
    rep["rows"], rep["cols"] = len(df), df.shape[1]
    rep["col_count_ok"] = df.shape[1] == EXPECTED_COLS
    rep["dup_cols"] = df.columns[df.columns.duplicated()].tolist()
    num = df.select_dtypes("number")
    rep["inf_cells"] = int(np.isinf(num).sum().sum())
    rep["nan_cells"] = int(num.isna().sum().sum())
    rep["id_cols_present"] = [c for c in ID_COLS if c in df.columns]
    return rep, len(df)


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/control":
            STATE["mode"] = parse_qs(u.query).get("mode", ["ok"])[0]
            return self._send(200, STATE)
        self._send(404, {})

    def do_POST(self):
        if urlparse(self.path).path != "/predict":
            return self._send(404, {"error": "not found"})
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        mode = STATE["mode"]
        entry = {"t": time.time(), "mode": mode}
        try:
            fields, files = parse_multipart(self.headers, body)
            entry.update(user_id=fields.get("user_id"), computer_id=fields.get("computer_id"))
            fname, data = files["file"]
            entry["filename"] = fname
            entry["report"], n = validate(data)
        except Exception as e:  # malformed request
            entry["error"] = repr(e)
            self._log(entry)
            return self._send(400, {"error": repr(e)})
        self._log(entry)
        if mode == "fail":
            return self._send(500, {"error": "simulated failure"})
        if mode == "slow":
            time.sleep(200)
        self._send(200, {"predictions": ["BENIGN"] * n, "rows": n})

    def _log(self, entry):
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8000
    print(f"Mock ML engine running on http://{HOST}:{PORT} (log={LOG}, mode={STATE['mode']})", flush=True)
    ThreadingHTTPServer((HOST, PORT), H).serve_forever()

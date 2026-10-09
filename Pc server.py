#!/usr/bin/env python3
"""Phone -> PC panel: send/receive files and use the command line from a browser.

Run:  python pc_server.py        then open http://<pc-ip>:8001 on your phone.

SECURITY: whoever knows the password gets a shell as YOUR user on this PC.
Keep it on your home Wi-Fi, use a strong password, never port-forward it
to the internet. Traffic is plain HTTP (fine at home, not on public Wi-Fi).
"""
import codecs, fcntl, hmac, json, mimetypes, os, pty, secrets, shutil, signal
import socket, struct, subprocess, termios, threading, time
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote

# ============================ CONFIG: EDIT THESE ============================
PORT = int(os.environ.get("PC_PORT", "8008"))
# Folder the file browser can see. "~" = your home folder, "/" = the whole PC.
ROOT_DIR = os.environ.get("PC_ROOT", "/")
# Login password. Leave empty to get a new random one printed at every start.
PASSWORD = os.environ.get("PC_PASSWORD", "2307")
# Shell used by the command line (needs bash).
SHELL_BIN = os.environ.get("PC_SHELL", "/bin/bash")
# ===========================================================================

HERE = Path(__file__).parent
ROOT = Path(ROOT_DIR).expanduser().resolve()
SESSIONS = set()
FAILS = {}  # ip -> [count, blocked_until]


def safe(rel):
    full = (ROOT / str(rel).lstrip("/")).resolve()
    if full != ROOT and ROOT not in full.parents:
        raise PermissionError("outside the allowed folder")
    return full


# --------------------------------- terminal ---------------------------------
def _child_setup():
    # runs in the new shell process: own the terminal, and make Ctrl+C work even
    # if this script was started in the background (which can ignore SIGINT)
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
    for sig in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP):
        signal.signal(sig, signal.SIG_DFL)


class Term:
    def __init__(self, cols=80, rows=24):
        self.cond = threading.Condition()
        self.buf, self.base, self.alive = "", 0, True
        master, slave = pty.openpty()
        self.fd = master
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO  # the web page echoes what you type itself
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        env = dict(os.environ, TERM="xterm-256color", PS1=r"\u@\h:\w\$ ", COLUMNS=str(cols), LINES=str(rows))
        self.proc = subprocess.Popen(
            [SHELL_BIN, "--noediting", "-i"], stdin=slave, stdout=slave, stderr=slave,
            cwd=str(ROOT), env=env, start_new_session=True, close_fds=True,
            preexec_fn=_child_setup)
        os.close(slave)
        threading.Thread(target=self._read, daemon=True).start()

    def _append(self, text):
        with self.cond:
            self.buf += text
            if len(self.buf) > 400_000:
                cut = len(self.buf) - 300_000
                self.buf, self.base = self.buf[cut:], self.base + cut
            self.cond.notify_all()

    def _read(self):
        dec = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            try:
                data = os.read(self.fd, 65536)
            except OSError:
                break
            if not data:
                break
            self._append(dec.decode(data))
        self.proc.wait()
        self.alive = False
        self._append("\r\n[shell exited - press Restart]\r\n")
        try:
            os.close(self.fd)
        except OSError:
            pass

    def write(self, data):
        if self.alive:
            os.write(self.fd, data.encode())

    def resize(self, cols, rows):
        if self.alive:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def kill(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGHUP)
            except OSError:
                self.proc.terminate()

    def stream(self, h, pos):
        h.send_response(200)
        h.send_header("Content-Type", "text/event-stream")
        h.send_header("Cache-Control", "no-cache")
        h.send_header("Connection", "close")
        h.end_headers()
        h.close_connection = True
        try:
            while TERM[0] is self:
                with self.cond:
                    if pos < self.base:
                        pos = self.base
                    if pos >= self.base + len(self.buf):
                        self.cond.wait(timeout=15)
                    end = self.base + len(self.buf)
                    chunk = self.buf[max(pos - self.base, 0):] if pos < end else ""
                if chunk:
                    pos = end
                    h.wfile.write(f"id: {pos}\ndata: {json.dumps(chunk)}\n\n".encode())
                else:
                    h.wfile.write(b": keepalive\n\n")
                h.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


TERM = [None]
TERM_LOCK = threading.Lock()


def get_term(cols=80, rows=24, restart=False):
    with TERM_LOCK:
        t = TERM[0]
        if t and (restart or not t.alive):
            t.kill()
            t = None
        if not t:
            t = TERM[0] = Term(cols, rows)
        return t


# ----------------------------------- HTTP -----------------------------------
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    # helpers
    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def jbody(self):
        try:
            return json.loads(self.body() or b"{}")
        except Exception:
            return {}

    def send_bytes(self, data, ctype, code=200, extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, code=200, extra=()):
        self.send_bytes(json.dumps(obj).encode(), "application/json", code, extra)

    def authed(self):
        c = SimpleCookie(self.headers.get("Cookie") or "")
        return "pcsid" in c and c["pcsid"].value in SESSIONS

    def same_origin(self):
        o = self.headers.get("Origin")
        return not o or urlparse(o).netloc == self.headers.get("Host")

    # routes
    def login(self):
        ip = self.client_address[0]
        cnt, until = FAILS.get(ip, [0, 0])
        if time.time() < until:
            return self.send_json({"error": "Too many attempts. Wait a minute."}, 429)
        pw = str(self.jbody().get("password", ""))
        if hmac.compare_digest(pw.encode(), PASSWORD.encode()):
            FAILS.pop(ip, None)
            sid = secrets.token_urlsafe(32)
            SESSIONS.add(sid)
            return self.send_json({"ok": True}, extra=[
                ("Set-Cookie", f"pcsid={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000")])
        time.sleep(1)
        cnt += 1
        FAILS[ip] = [0, time.time() + 60] if cnt >= 5 else [cnt, 0]
        self.send_json({"error": "Wrong password."}, 401)

    def ls(self, q):
        d = safe(q.get("path", [""])[0])
        if not d.is_dir():
            raise NotADirectoryError("not a folder")
        items = []
        for e in os.scandir(d):
            try:
                st, isd = e.stat(), e.is_dir()
            except OSError:
                continue
            items.append({"name": e.name, "dir": isd, "size": st.st_size, "mtime": int(st.st_mtime)})
        items.sort(key=lambda x: (not x["dir"], x["name"].lower()))
        rel = "" if d == ROOT else str(d.relative_to(ROOT))
        self.send_json({"path": rel, "items": items})

    def download(self, q):
        f = safe(q.get("path", [""])[0])
        if not f.is_file():
            raise FileNotFoundError("no such file")
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(f.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(f.stat().st_size))
        self.send_header("Content-Disposition", "attachment; filename*=UTF-8''" + quote(f.name))
        self.end_headers()
        with open(f, "rb") as fh:
            shutil.copyfileobj(fh, self.wfile, 1 << 20)

    def upload(self, q):
        d = safe(q.get("path", [""])[0])
        name = os.path.basename(q.get("name", [""])[0]).strip()
        if not d.is_dir() or name in ("", ".", ".."):
            raise ValueError("bad folder or file name")
        remaining = int(self.headers.get("Content-Length") or -1)
        if remaining < 0:
            return self.send_json({"error": "Content-Length required"}, 411)
        dest, i = d / name, 1
        while dest.exists():
            stem, suf = os.path.splitext(name)
            dest, i = d / f"{stem} ({i}){suf}", i + 1
        tmp = dest.with_name(dest.name + ".part")
        with open(tmp, "wb") as f:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)
        if remaining:
            tmp.unlink(missing_ok=True)
            raise ValueError("upload interrupted")
        tmp.rename(dest)
        self.send_json({"ok": True, "name": dest.name})

    def handle_any(self, method):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        try:
            if p in ("/", "/index.html") and method == "GET":
                return self.send_bytes((HERE / "pc.html").read_bytes(), "text/html; charset=utf-8")
            if method != "GET" and not self.same_origin():
                return self.send_json({"error": "bad origin"}, 403)
            if p == "/api/login" and method == "POST":
                return self.login()
            if not p.startswith("/api/"):
                return self.send_json({"error": "not found"}, 404)
            if not self.authed():
                return self.send_json({"error": "login required"}, 401)

            if p == "/api/auth":
                return self.send_json({"ok": True, "root": str(ROOT)})
            if p == "/api/ls" and method == "GET":
                return self.ls(q)
            if p == "/api/download" and method == "GET":
                return self.download(q)
            if p == "/api/upload" and method == "POST":
                return self.upload(q)
            if p == "/api/mkdir" and method == "POST":
                b = self.jbody()
                name = os.path.basename(str(b.get("name", ""))).strip()
                if name in ("", ".", ".."):
                    raise ValueError("bad name")
                (safe(b.get("path", "")) / name).mkdir()
                return self.send_json({"ok": True})
            if p == "/api/delete" and method == "POST":
                t = safe(self.jbody().get("path", ""))
                if t == ROOT:
                    raise PermissionError("cannot delete the root folder")
                shutil.rmtree(t) if t.is_dir() and not t.is_symlink() else t.unlink()
                return self.send_json({"ok": True})

            if p == "/api/term/start" and method == "POST":
                b = self.jbody()
                get_term(int(b.get("cols", 80)), int(b.get("rows", 24)), restart=bool(b.get("restart")))
                return self.send_json({"ok": True})
            if p == "/api/term/stream" and method == "GET":
                t = TERM[0] or get_term()
                last = self.headers.get("Last-Event-ID") or q.get("pos", ["0"])[0]
                return t.stream(self, int(last) if str(last).isdigit() else 0)
            if p == "/api/term/input" and method == "POST":
                get_term().write(str(self.jbody().get("data", "")))
                return self.send_json({"ok": True})
            if p == "/api/term/resize" and method == "POST":
                b = self.jbody()
                get_term().resize(int(b.get("cols", 80)), int(b.get("rows", 24)))
                return self.send_json({"ok": True})
            self.send_json({"error": "not found"}, 404)
        except PermissionError as e:
            self.send_json({"error": str(e)}, 403)
        except FileNotFoundError as e:
            self.send_json({"error": str(e)}, 404)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception as e:
            self.send_json({"error": str(e)}, 400)

    def do_GET(self): self.handle_any("GET")
    def do_POST(self): self.handle_any("POST")


def lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # no traffic is sent; just picks the Wi-Fi interface
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "<pc-ip>"


if __name__ == "__main__":
    if not PASSWORD:
        PASSWORD = secrets.token_urlsafe(9)
        print(f"Password (new every start; set PC_PASSWORD to keep one): {PASSWORD}")
    print(f"File browser root : {ROOT}")
    print(f"Open on your phone: http://{lan_ip()}:{PORT}")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
    except KeyboardInterrupt:
        if TERM[0]:
            TERM[0].kill()

#!/usr/bin/env python3
"""Phone -> PC panel: files, command line, desktop view (screenshot + live view),
and an LLM tab (llama.cpp chat + an agent that can work on this PC) in a browser.

Run:  python pc_server.py        then open http://<pc-ip>:8001 on your phone.

SECURITY: whoever knows the password gets a shell as YOUR user on this PC, and so
does the LLM agent (the phone asks before it runs a command, unless you turn that off).
Keep it on your home Wi-Fi, use a strong password, never port-forward it
to the internet. Traffic is plain HTTP (fine at home, not on public Wi-Fi).
"""
import atexit, codecs, difflib, fcntl, hmac, ipaddress, json, mimetypes, os, pty, secrets, shutil, signal
import re, socket, struct, subprocess, termios, threading, time
import urllib.error, urllib.request
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs, quote

# ============================ CONFIG: EDIT THESE ============================
PORT = int(os.environ.get("PC_PORT", "8001"))
# Folder the file browser can see. "~" = your home folder, "/" = the whole PC.
ROOT_DIR = os.environ.get("PC_ROOT", "~")
# Login password. Leave empty to get a new random one printed at every start.
PASSWORD = os.environ.get("PC_PASSWORD", "")
# TEMPORARY debugging switch: PC_NOAUTH=1 python pc_server.py  -> no login at all.
# Only devices on your home network (private IPs) are let in; everyone else gets 401.
NO_AUTH = os.environ.get("PC_NOAUTH") == "1"
# Shell used by the command line (needs bash).
SHELL_BIN = os.environ.get("PC_SHELL", "/bin/bash")
# X display to capture (the one your desktop runs on).
DISPLAY = os.environ.get("PC_DISPLAY") or os.environ.get("DISPLAY") or ":0"
# Live view stops by itself after this many seconds, to keep the PC's CPU free.
STREAM_MAX = int(os.environ.get("PC_STREAM_MAX", "120"))

# --- LLM tab (llama.cpp): copy the values you used in your old server.py ---
# llama-server must sit next to llama-cli (llama-cli itself has no HTTP API).
LLAMA_CLI = os.environ.get("LLAMA_CLI", "/home/you/llama.cpp/build/bin/llama-cli")
LLAMA_SERVER = os.environ.get("LLAMA_SERVER", str(Path(LLAMA_CLI).expanduser().with_name("llama-server")))
# Folder with your models. Every subfolder is scanned for *.gguf files.
MODELS_DIR = os.environ.get("MODELS_DIR", "/home/you/models")
# Extra flags for llama-server, e.g. ["--jinja", "-ngl", "99", "-c", "8192"]. --jinja is needed for the agent.
EXTRA_ARGS = ["--jinja"]
LLAMA_PORT = int(os.environ.get("LLAMA_PORT", "8081"))  # internal, not exposed
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


# ------------------------- screenshot and live view -------------------------
FFMPEG = shutil.which("ffmpeg")
CAP_ENV = dict(os.environ, DISPLAY=DISPLAY)
SHOT_LOCK = threading.Lock()
STREAM, STREAM_LOCK = [None], threading.Lock()


def _shot_tools():
    tools = []
    if FFMPEG:
        tools.append([FFMPEG, "-loglevel", "error", "-f", "x11grab", "-i", DISPLAY,
                      "-frames:v", "1", "-f", "image2pipe", "-c:v", "png", "-"])
    if shutil.which("maim"):
        tools.append(["maim"])
    if shutil.which("import"):  # ImageMagick
        tools.append(["import", "-window", "root", "png:-"])
    if shutil.which("grim"):  # Wayland
        if os.environ.get("XDG_SESSION_TYPE") == "wayland":
            tools.insert(0, ["grim", "-"])  # x11grab would only see X apps
        else:
            tools.append(["grim", "-"])
    return tools


SHOT_TOOLS = _shot_tools()


def screenshot():
    with SHOT_LOCK:
        for cmd in SHOT_TOOLS:
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=15, env=CAP_ENV, stdin=subprocess.DEVNULL)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if r.returncode == 0 and r.stdout[:4] == b"\x89PNG":
                return r.stdout
    raise RuntimeError("screenshot failed - is DISPLAY right? install ffmpeg or maim (X11) / grim (Wayland)")


def stop_stream():
    with STREAM_LOCK:
        p, STREAM[0] = STREAM[0], None
    if p and p.poll() is None:
        p.kill()


def stream_screen(h, q):
    """Live view as MJPEG (multipart JPEG): plays in a plain <img> on any phone."""
    if not FFMPEG:
        raise RuntimeError("live view needs ffmpeg (sudo pacman -S ffmpeg)")

    def num(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(q.get(key, [default])[0])))
        except ValueError:
            return default

    fps, w, qual = num("fps", 10, 1, 30), num("w", 720, 240, 1920), num("q", 8, 2, 31)
    cmd = [FFMPEG, "-loglevel", "error", "-f", "x11grab", "-framerate", str(fps), "-i", DISPLAY,
           "-t", str(STREAM_MAX), "-vf", f"scale={w}:-2", "-c:v", "mjpeg", "-q:v", str(qual),
           "-flush_packets", "1", "-f", "mpjpeg", "-boundary_tag", "frame", "pipe:1"]
    with STREAM_LOCK:  # only one live view at a time; a new one replaces the old
        if STREAM[0] and STREAM[0].poll() is None:
            STREAM[0].kill()
        p = STREAM[0] = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE, env=CAP_ENV)
    try:
        first = p.stdout.read1(65536)
        if not first:
            err = p.stderr.read().decode(errors="replace").strip().splitlines()
            raise RuntimeError(err[-1] if err else "ffmpeg could not start")
        h.send_response(200)
        h.send_header("Content-Type", "multipart/x-mixed-replace;boundary=frame")
        h.send_header("Cache-Control", "no-store")
        h.send_header("Connection", "close")
        h.end_headers()
        h.close_connection = True
        try:
            h.wfile.write(first)
            while True:
                chunk = p.stdout.read1(65536)
                if not chunk:
                    break
                h.wfile.write(chunk)
        except OSError:  # phone closed the stream
            pass
    finally:
        p.kill()
        p.wait()
        p.stdout.close()
        p.stderr.close()


# ------------------------------- LLM (llama.cpp) -------------------------------
CHATS = HERE / "chats"
CHATS.mkdir(exist_ok=True)
LOG = HERE / "llama-server.log"
ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SHARD = re.compile(r"-(\d+)-of-\d+\.gguf$", re.I)
UPSTREAM = f"http://127.0.0.1:{LLAMA_PORT}"


# ------------------------------ model scanning ------------------------------
def find_mmproj(model: Path):
    cands = [f for f in model.parent.glob("*.gguf") if "mmproj" in f.name.lower()]
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    return max(cands, key=lambda f: difflib.SequenceMatcher(None, f.stem.lower(), model.stem.lower()).ratio())


def scan_models():
    root = Path(MODELS_DIR).expanduser()
    found = {}
    if not root.is_dir():
        return found
    for dirpath, _dirs, files in os.walk(root, followlinks=True):
        for name in sorted(files):
            if not name.lower().endswith(".gguf") or "mmproj" in name.lower():
                continue
            m = SHARD.search(name)
            if m and int(m.group(1)) != 1:  # only list the first shard of split models
                continue
            f = Path(dirpath) / name
            rid = str(f.relative_to(root))
            found[rid] = {"id": rid, "name": rid[:-5], "path": f,
                          "size": f.stat().st_size, "mmproj": find_mmproj(f)}
    return dict(sorted(found.items()))


# ------------------------------ llama-server -------------------------------
class Llama:
    def __init__(self):
        self.proc = None
        self.loaded = None
        self.state = "idle"  # idle | loading | ready | error
        self.error = ""
        self.lock = threading.Lock()

    def snapshot(self):
        if self.state in ("ready", "loading") and self.proc and self.proc.poll() is not None:
            self.state, self.error = "error", "llama-server exited.\n" + self.log_tail()
        return self.state

    def log_tail(self, n=8):
        try:
            return "\n".join(LOG.read_text(errors="ignore").strip().splitlines()[-n:])
        except Exception:
            return ""

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc, self.loaded, self.state = None, None, "idle"

    def healthy(self):
        try:
            with urllib.request.urlopen(UPSTREAM + "/health", timeout=2) as r:
                return r.status == 200
        except Exception:
            return False

    def load(self, rid):
        model = scan_models().get(rid)
        if not model:
            return False, "Model not found in MODELS_DIR."
        if not Path(LLAMA_SERVER).expanduser().exists():
            return False, f"llama-server not found at {LLAMA_SERVER}. Fix LLAMA_CLI / LLAMA_SERVER."
        with self.lock:
            if self.loaded == rid and self.snapshot() == "ready":
                return True, ""
            self.stop()
            self.state, self.error = "loading", ""
            cmd = [str(Path(LLAMA_SERVER).expanduser()), "-m", str(model["path"]),
                   "--host", "127.0.0.1", "--port", str(LLAMA_PORT)]
            if model["mmproj"]:
                cmd += ["--mmproj", str(model["mmproj"])]
            cmd += EXTRA_ARGS
            with open(LOG, "w") as lf:
                lf.write("$ " + " ".join(cmd) + "\n")
                self.proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT)
            self.loaded = rid
            deadline = time.time() + 900
            while time.time() < deadline:
                if self.proc.poll() is not None:
                    self.state, self.error = "error", "llama-server exited.\n" + self.log_tail()
                    self.loaded = None
                    return False, self.error
                if self.healthy():
                    self.state = "ready"
                    return True, ""
                time.sleep(1)
            self.stop()
            self.state, self.error = "error", "Timed out waiting for the model to load."
            return False, self.error


llama = Llama()
atexit.register(llama.stop)


# ------------------------------- agent tools --------------------------------
def _clip(s, n=6000):
    return s if len(s) <= n else s[: n // 2] + f"\n[... {len(s) - n} chars cut ...]\n" + s[-n // 2:]


def _agent_path(p):
    p = Path(str(p)).expanduser()
    return p if p.is_absolute() else ROOT / p


def agent_tool(name, a):
    """Run one tool call from the LLM agent. The phone asks you before run_command / write_file."""
    if name == "run_command":
        cmd = str(a.get("command", "")).strip()
        if not cmd:
            raise ValueError("empty command")
        try:
            limit = max(1, min(300, int(a.get("timeout") or 60)))
        except (TypeError, ValueError):
            limit = 60
        p = subprocess.Popen(["bash", "-c", cmd], cwd=str(ROOT), stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                             env=dict(CAP_ENV, TERM="dumb"))
        note = ""
        try:
            out, _ = p.communicate(timeout=limit)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            try:
                out, _ = p.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                out = b""
            note = f"\n[killed after {limit}s]"
        return _clip(out.decode(errors="replace").rstrip()) + note + f"\n[exit {p.returncode}]"
    if name == "read_file":
        with open(_agent_path(a.get("path", "")), "rb") as fh:
            data = fh.read(20001)
        return data[:20000].decode(errors="replace") + ("\n[... truncated ...]" if len(data) > 20000 else "")
    if name == "write_file":
        f = _agent_path(a.get("path", ""))
        f.parent.mkdir(parents=True, exist_ok=True)
        text = str(a.get("content", ""))
        f.write_text(text)
        return f"wrote {len(text.encode())} bytes to {f}"
    raise ValueError(f"unknown tool: {name}")


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
        if NO_AUTH:
            try:
                ip = ipaddress.ip_address(self.client_address[0].split("%")[0])
                ip = getattr(ip, "ipv4_mapped", None) or ip  # ::ffff:192.168.x.x -> 192.168.x.x
                return ip.is_private
            except ValueError:
                return False
        c = SimpleCookie(self.headers.get("Cookie") or "")
        return "pcsid" in c and c["pcsid"].value in SESSIONS

    def same_origin(self):
        o = self.headers.get("Origin")
        return not o or urlparse(o).netloc == self.headers.get("Host")

    def proxy(self, method):
        url = UPSTREAM + self.path[len("/api/llm"):]
        data = self.body() if method == "POST" else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            up = urllib.request.urlopen(req, timeout=900)
            code = up.status
        except urllib.error.HTTPError as e:
            up, code = e, e.code
        except Exception as e:
            return self.send_json({"error": f"llama-server not reachable: {e}"}, 502)
        self.send_response(code)
        self.send_header("Content-Type", up.headers.get("Content-Type", "application/json"))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        read = getattr(up, "read1", up.read)
        try:
            while True:
                chunk = read(4096)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # Stop pressed on the phone: closing upstream stops generation
        finally:
            up.close()
            self.close_connection = True

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

            if p == "/api/screen/info" and method == "GET":
                return self.send_json({"shot": bool(SHOT_TOOLS), "stream": bool(FFMPEG), "max": STREAM_MAX})
            if p == "/api/screen/shot" and method == "GET":
                return self.send_bytes(screenshot(), "image/png", extra=[("Cache-Control", "no-store")])
            if p == "/api/screen/stream" and method == "GET":
                return stream_screen(self, q)

            if p == "/api/llm/models" and method == "GET":
                models = [{"id": m["id"], "name": m["name"], "vision": bool(m["mmproj"]),
                           "size_gb": round(m["size"] / 1e9, 1)} for m in scan_models().values()]
                return self.send_json({"models": models, "loaded": llama.loaded,
                                       "state": llama.snapshot(), "error": llama.error})
            if p == "/api/llm/status" and method == "GET":
                return self.send_json({"loaded": llama.loaded, "state": llama.snapshot(), "error": llama.error})
            if p == "/api/llm/load" and method == "POST":
                ok, err = llama.load(str(self.jbody().get("id", "")))
                return self.send_json({"ok": ok, "error": err}, 200 if ok else 500)
            if p == "/api/llm/unload" and method == "POST":
                if llama.state == "loading":
                    return self.send_json({"error": "the model is still loading"}, 409)
                llama.stop()
                return self.send_json({"ok": True})
            if p.startswith("/api/llm/v1/"):
                return self.proxy(method)
            if p == "/api/llm/chats" and method == "GET":
                items = []
                for f in CHATS.glob("*.json"):
                    try:
                        c = json.loads(f.read_text())
                        items.append({"id": c["id"], "title": c.get("title", "New chat"), "updated": c.get("updated", 0)})
                    except Exception:
                        pass
                items.sort(key=lambda x: x["updated"], reverse=True)
                return self.send_json(items)
            m = re.match(r"^/api/llm/chats/([^/]+)$", p)
            if m and ID.match(m.group(1)):
                f = CHATS / (m.group(1) + ".json")
                if method == "GET":
                    return self.send_bytes(f.read_bytes(), "application/json") if f.exists() else self.send_json({}, 404)
                if method == "PUT":
                    f.write_bytes(self.body())
                    return self.send_json({"ok": True})
                if method == "DELETE":
                    f.unlink(missing_ok=True)
                    return self.send_json({"ok": True})
            if p == "/api/agent/tool" and method == "POST":
                b = self.jbody()
                return self.send_json({"output": agent_tool(str(b.get("name", "")), b.get("args") or {})})

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
    def do_PUT(self): self.handle_any("PUT")
    def do_DELETE(self): self.handle_any("DELETE")


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
    if NO_AUTH:
        print("!!! PC_NOAUTH=1: NO PASSWORD. Anyone on your Wi-Fi/LAN gets a shell on this PC. Debug only, then restart normally.")
    elif not PASSWORD:
        PASSWORD = secrets.token_urlsafe(9)
        print(f"Password (new every start; set PC_PASSWORD to keep one): {PASSWORD}")
    print(f"File browser root : {ROOT}")
    print(f"Screen capture    : {', '.join(c[0] for c in SHOT_TOOLS) or 'NONE (install ffmpeg or maim)'}"
          f" on {DISPLAY}; live view {'on' if FFMPEG else 'OFF (needs ffmpeg)'}")
    print(f"LLM               : llama-server {'ok' if Path(LLAMA_SERVER).expanduser().exists() else 'NOT FOUND (set LLAMA_CLI)'}; "
          f"{len(scan_models())} gguf models in {MODELS_DIR}")
    print(f"Open on your phone: http://{lan_ip()}:{PORT}")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
    except KeyboardInterrupt:
        stop_stream()
        if TERM[0]:
            TERM[0].kill()

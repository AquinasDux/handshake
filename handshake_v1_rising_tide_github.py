import ctypes
import json
import queue
import select
import socket
import sys
import threading
import time

PORT = 5000
DISCOVERY_PORT = 5001
DISCOVERY_MSG = b"HANDSHAKE_DISCOVER"
BUFFER_SIZE = 4096
MAX_LINE_BYTES = 65536
PASTE_WINDOW = 0.05
APP_VERSION = "V1"
APP_CODENAME = "Rising Tide"



def _enable_windows_ansi():
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


_enable_windows_ansi()
IS_TTY = sys.stdout.isatty()

_input_queue = queue.Queue()


def _stdin_reader():
    while True:
        try:
            line = input()
        except EOFError:
            _input_queue.put(None)
            return
        _input_queue.put(line)


threading.Thread(target=_stdin_reader, daemon=True).start()


def read_line(prompt=""):
    if prompt:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    line = _input_queue.get()
    if line is None:
        raise EOFError
    return line


def _code(seq):
    return seq if IS_TTY else ""


RESET = _code("\033[0m")
DIM = _code("\033[2m")
BOLD = _code("\033[1m")
BANNER_COLOR = _code("\033[1;31m")
PALETTE = [_code(s) for s in (
    "\033[36m", "\033[33m", "\033[35m", "\033[32m", "\033[31m", "\033[34m",
)]

_color_lock = threading.Lock()
_assigned = {}


def color_for(name):
    with _color_lock:
        if name not in _assigned:
            _assigned[name] = PALETTE[len(_assigned) % len(PALETTE)]
        return _assigned[name]


PROMPT = f"{BOLD}You:{RESET} "

HELP_TEXT = (
    f"{DIM}Commands:{RESET}\n"
    "  /help      Show this list\n"
    "  /hostname  Show this device's hostname\n"
    "  /ip        List everyone connected and their IP address\n"
    "  /ping      Check connection latency (ms)\n"
    "  /quit      Leave the chat (same as typing 'exit')"
)


def _sgr(code):
    return _code(f"\033[{code}m")


def print_banner():
    title = f"Handshake {APP_VERSION} ({APP_CODENAME})"
    width = max(len(title), 30) + 4
    print()
    print(f"{BANNER_COLOR}{title.center(width)}{RESET}")
    print(f"{DIM}{'LAN Terminal Chat'.center(width)}{RESET}")
    print()


def fmt_chat(name, text):
    return f"{color_for(name)}[{name}]{RESET}: {text}"


def fmt_status(name, suffix):
    return f"{DIM}-{RESET}{color_for(name)}{name}{RESET}{DIM} {suffix}-{RESET}"


def fmt_plain_status(text):
    return f"{DIM}-{text}-{RESET}"


def print_incoming(block):
    if IS_TTY:
        sys.stdout.write("\r\033[2K")
    print(block)
    sys.stdout.write(PROMPT)
    sys.stdout.flush()


def get_identity():
    return socket.gethostname()


def _all_local_ips():
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    for target in ("192.168.1.1", "10.0.0.1", "172.16.0.1"):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((target, 80))
            ip = s.getsockname()[0]
            if not ip.startswith("127."):
                ips.add(ip)
        except OSError:
            pass
        finally:
            s.close()
    return ips or {"127.0.0.1"}


def get_local_ip():
    ips = _all_local_ips()
    ips.discard("127.0.0.1")
    return next(iter(ips)) if ips else "127.0.0.1"


def _local_ips():
    return _all_local_ips()


def _subnet_for(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3])
    return None


def _sweep_subnet(subnet, own_ips, found, timeout=1.5):
    results = {}
    targets = [f"{subnet}.{i}" for i in range(1, 255) if f"{subnet}.{i}" not in own_ips]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.08)

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        recv_sock.bind(("", 0))
    except OSError:
        sock.close()
        recv_sock.close()
        return results
    recv_sock.settimeout(0.1)

    end = time.time() + timeout
    batch = 0
    while time.time() < end and batch < len(targets):
        for ip in targets[batch:batch + 25]:
            try:
                sock.sendto(DISCOVERY_MSG, (ip, DISCOVERY_PORT))
            except OSError:
                pass
        batch += 25
        deadline = min(time.time() + 0.3, end)
        while time.time() < deadline:
            try:
                data, addr = recv_sock.recvfrom(1024)
                info = json.loads(data.decode("utf-8"))
                if info.get("service") == "handshake_chat" and addr[0] not in own_ips:
                    results[addr[0]] = info.get("name", addr[0])
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                pass

    sock.close()
    recv_sock.close()
    return results


def discover_hosts(timeout=1.5):
    found = {}
    socks = []
    own_ips = _all_local_ips() | {"127.0.0.1"}

    for ip in own_ips - {"127.0.0.1"}:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            s.bind((ip, 0))
        except OSError:
            s.close()
            continue
        socks.append(s)
    wildcard = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    wildcard.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    wildcard.bind(("", 0))
    socks.append(wildcard)

    def broadcast():
        for s in socks:
            try:
                s.sendto(DISCOVERY_MSG, ("255.255.255.255", DISCOVERY_PORT))
            except OSError:
                pass

    end = time.time() + timeout
    last_sent = 0.0
    while time.time() < end:
        if time.time() - last_sent > 0.4:
            broadcast()
            last_sent = time.time()
        remaining = max(0.0, min(0.3, end - time.time()))
        ready, _, _ = select.select(socks, [], [], remaining)
        for s in ready:
            try:
                data, addr = s.recvfrom(1024)
            except OSError:
                continue
            try:
                info = json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if info.get("service") == "handshake_chat" and addr[0] not in own_ips:
                found[addr[0]] = info.get("name", addr[0])

    for s in socks:
        s.close()

    if not found:
        subnets = set()
        for ip in own_ips - {"127.0.0.1"}:
            s = _subnet_for(ip)
            if s:
                subnets.add(s)
        for subnet in subnets:
            found.update(_sweep_subnet(subnet, own_ips, found))

    return found


def _safe(fn):
    try:
        fn()
    except OSError:
        pass


class MessageStream:
    def __init__(self, sock):
        self.sock = sock
        self.buffer = b""
        self._send_lock = threading.Lock()

    def send(self, msg):
        data = (json.dumps(msg) + "\n").encode("utf-8")
        with self._send_lock:
            self.sock.sendall(data)

    def read(self):
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_LINE_BYTES:
                return None
            try:
                chunk = self.sock.recv(BUFFER_SIZE)
            except OSError:
                return None
            if not chunk:
                return None
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        if not line.strip():
            return {}
        try:
            return json.loads(line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {}

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class Host:
    def __init__(self, name):
        self.name = name
        self.clients = {}
        self.lock = threading.Lock()
        self.server_sock = None
        self.running = False
        self._accept_thread = None
        self._discovery_sock = None
        self._discovery_thread = None

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("0.0.0.0", PORT))
        self.server_sock.listen(5)
        self.server_sock.settimeout(0.3)
        self.running = True
        print(f"\n--- Hosting as {self.name} ---")
        print(f"Others can join with: {get_local_ip()}  (port {PORT})")
        print("Waiting for connections...\n")
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        self._start_discovery_responder()

    def _start_discovery_responder(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", DISCOVERY_PORT))
        except OSError:
            sock.close()
            return
        sock.settimeout(0.5)
        self._discovery_sock = sock
        self._discovery_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self._discovery_thread.start()

    def _discovery_loop(self):
        reply = json.dumps({"service": "handshake_chat", "name": self.name}).encode("utf-8")
        while self.running:
            try:
                data, addr = self._discovery_sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                return
            if data == DISCOVERY_MSG:
                _safe(lambda: self._discovery_sock.sendto(reply, addr))

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()

    def _unique_name(self, requested):
        with self.lock:
            taken = {info["name"] for info in self.clients.values()}
        taken.add(self.name)
        if requested not in taken:
            return requested
        i = 2
        while f"{requested}-{i}" in taken:
            i += 1
        return f"{requested}-{i}"

    def _handle_client(self, conn, addr):
        stream = MessageStream(conn)
        first = stream.read()
        if not first or first.get("type") != "join":
            stream.close()
            return

        name = self._unique_name(str(first.get("name") or "Guest")[:30])
        stream.send({"type": "join_ack", "name": name})

        with self.lock:
            self.clients[conn] = {"stream": stream, "name": name, "ip": addr[0]}
        color_for(name)
        print_incoming(fmt_status(name, "connected"))
        self._broadcast({"type": "status", "name": name, "event": "connected"}, exclude=conn)

        while True:
            msg = stream.read()
            if msg is None:
                break
            mtype = msg.get("type")
            if mtype == "chat":
                text = str(msg.get("text", ""))
                print_incoming(fmt_chat(name, text))
                self._broadcast({"type": "chat", "name": name, "text": text}, exclude=conn)
            elif mtype == "ping":
                _safe(lambda: stream.send({"type": "pong", "sent_at": msg.get("sent_at")}))
            elif mtype == "pong":
                sent_at = msg.get("sent_at")
                if isinstance(sent_at, (int, float)):
                    rtt_ms = (time.time() - sent_at) * 1000
                    print_incoming(fmt_plain_status(f"Ping to {name}: {rtt_ms:.0f} ms"))
            elif mtype == "roster_request":
                _safe(lambda: stream.send({"type": "roster_response", "entries": self._roster_entries()}))
            elif mtype == "leave":
                break

        with self.lock:
            self.clients.pop(conn, None)
        stream.close()
        print_incoming(fmt_status(name, "disconnected"))
        self._broadcast({"type": "status", "name": name, "event": "disconnected"}, exclude=conn)

    def _roster_entries(self):
        with self.lock:
            entries = [{"name": info["name"], "ip": info["ip"]} for info in self.clients.values()]
        entries.append({"name": f"{self.name} (host)", "ip": get_local_ip()})
        return entries

    def _broadcast(self, msg, exclude=None):
        with self.lock:
            streams = [info["stream"] for c, info in self.clients.items() if c != exclude]
        for s in streams:
            _safe(lambda s=s: s.send(msg))

    def send_chat(self, text):
        self._broadcast({"type": "chat", "name": self.name, "text": text})

    def announce_leaving(self):
        self._broadcast({"type": "status", "name": self.name, "event": "host_left"})

    def handle_command(self, text):
        cmd = text.split()[0].lower()
        if cmd == "/help":
            print(HELP_TEXT)
        elif cmd == "/hostname":
            print(fmt_plain_status(f"Hostname: {socket.gethostname()}"))
        elif cmd == "/ip":
            self._print_roster()
        elif cmd == "/ping":
            self._ping_all()
        else:
            print(fmt_plain_status(f"Unknown command: {cmd} (try /help)"))

    def _print_roster(self):
        lines = [fmt_plain_status("Connected devices:")]
        for e in self._roster_entries():
            lines.append(f"  {e['name']}: {e['ip']}")
        print("\n".join(lines))

    def _ping_all(self):
        with self.lock:
            count = len(self.clients)
        if count == 0:
            print(fmt_plain_status("No one is connected to ping"))
            return
        self._broadcast({"type": "ping", "sent_at": time.time()})

    def shutdown(self):
        self.running = False
        with self.lock:
            conns = list(self.clients.keys())
            self.clients.clear()
        for c in conns:
            _safe(c.close)
        if self.server_sock:
            _safe(self.server_sock.close)
        if self._accept_thread:
            self._accept_thread.join(timeout=1.0)
        if self._discovery_sock:
            _safe(self._discovery_sock.close)
        if self._discovery_thread:
            self._discovery_thread.join(timeout=1.0)


class Client:
    def __init__(self, target_ip):
        self.name = get_identity()
        self.target_ip = target_ip
        self.stream = None
        self.sock = None
        self.connected = False

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.target_ip, PORT))
        self.sock.settimeout(None)
        self.stream = MessageStream(self.sock)
        self.stream.send({"type": "join", "name": self.name})

        ack = self.stream.read()
        if ack and ack.get("type") == "join_ack":
            final_name = ack.get("name", self.name)
            if final_name != self.name:
                print(f"('{self.name}' was taken - you're '{final_name}' for this chat)")
            self.name = final_name

        self.connected = True
        print(f"\n--- Connected to {self.target_ip} as {self.name} ---\n")
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def _receive_loop(self):
        while True:
            msg = self.stream.read()
            if msg is None:
                self.connected = False
                print_incoming(fmt_plain_status("Disconnected from host"))
                return
            mtype = msg.get("type")
            if mtype == "chat":
                print_incoming(fmt_chat(msg.get("name", "?"), str(msg.get("text", ""))))
            elif mtype == "status":
                name = msg.get("name", "?")
                event = msg.get("event")
                if event == "connected":
                    print_incoming(fmt_status(name, "connected"))
                elif event == "disconnected":
                    print_incoming(fmt_status(name, "disconnected"))
                elif event == "host_left":
                    print_incoming(fmt_plain_status("Host ended the chat"))
                    self.connected = False
                    return
            elif mtype == "ping":
                _safe(lambda: self.stream.send({"type": "pong", "sent_at": msg.get("sent_at")}))
            elif mtype == "pong":
                sent_at = msg.get("sent_at")
                if isinstance(sent_at, (int, float)):
                    rtt_ms = (time.time() - sent_at) * 1000
                    print_incoming(fmt_plain_status(f"Ping: {rtt_ms:.0f} ms"))
            elif mtype == "roster_response":
                lines = [fmt_plain_status("Connected devices:")]
                for e in msg.get("entries", []):
                    lines.append(f"  {e.get('name')}: {e.get('ip')}")
                print_incoming("\n".join(lines))

    def send_chat(self, text):
        self.stream.send({"type": "chat", "name": self.name, "text": text})

    def handle_command(self, text):
        cmd = text.split()[0].lower()
        if cmd == "/help":
            print(HELP_TEXT)
        elif cmd == "/hostname":
            print(fmt_plain_status(f"Hostname: {socket.gethostname()}"))
        elif cmd == "/ip":
            _safe(lambda: self.stream.send({"type": "roster_request"}))
        elif cmd == "/ping":
            _safe(lambda: self.stream.send({"type": "ping", "sent_at": time.time()}))
        else:
            print(fmt_plain_status(f"Unknown command: {cmd} (try /help)"))

    def leave(self):
        _safe(lambda: self.stream.send({"type": "leave"}))

    def close(self):
        if self.stream:
            self.stream.close()


def run_send_loop(participant, is_connected_fn):
    while True:
        if not is_connected_fn():
            return "disconnected"

        try:
            first_line = read_line(PROMPT)
        except EOFError:
            print()
            return "user_exit"

        lines = [first_line]
        while True:
            try:
                more = _input_queue.get(timeout=PASTE_WINDOW)
            except queue.Empty:
                break
            if more is None:
                _input_queue.put(None)
                break
            lines.append(more)

        if not is_connected_fn():
            return "disconnected"

        text = "\n".join(lines).strip()
        if not text:
            continue

        if len(lines) == 1:
            if text.lower() in ("exit", "/quit"):
                return "user_exit"
            if text.startswith("/"):
                participant.handle_command(text)
                continue

        try:
            participant.send_chat(text)
        except OSError:
            return "disconnected"


def choose_role():
    print("1. Host a chat (Server)")
    print("2. Join a chat (Client)")
    while True:
        choice = read_line("Select option (1 or 2): ").strip()
        if choice in ("1", "2"):
            return "host" if choice == "1" else "join"
        print("Invalid choice, try again.")


def ask_target_ip():
    print("Searching for a host on the network...")
    found = discover_hosts()

    own_ips = _all_local_ips() | {"127.0.0.1"}
    found = {ip: name for ip, name in found.items() if ip not in own_ips}

    if not found:
        target = read_line(
            "No host found automatically. Enter Host IP or Hostname (Press Enter for localhost): "
        ).strip()
        return target or "127.0.0.1"

    items = list(found.items())
    if len(items) == 1:
        ip, name = items[0]
        print(f"Found: {name} ({ip})")
        choice = read_line("Press Enter to join, or type a different IP: ").strip()
        return choice or ip

    print("Multiple hosts found:")
    for i, (ip, name) in enumerate(items, start=1):
        print(f"  {i}. {name} ({ip})")
    choice = read_line("Select a number, or type an IP: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(items):
        return items[int(choice) - 1][0]
    return choice or items[0][0]


def ask_restart():
    while True:
        choice = read_line(
            "\nPress [R] to restart, [M] to return to Main Menu, or [Q] to quit: "
        ).strip().lower()
        if choice in ("r", "m", "q"):
            return choice
        print("Please enter R, M, or Q.")


def run_host_session():
    host = Host(get_identity())
    try:
        host.start()
    except OSError as e:
        print(f"Couldn't start hosting: {e}")
        return

    reason = run_send_loop(host, lambda: host.running)
    if reason == "user_exit":
        host.announce_leaving()
        time.sleep(0.1)
    host.shutdown()
    print(fmt_plain_status("Chat ended"))


def run_client_session(target_ip):
    client = Client(target_ip)
    try:
        client.connect()
    except OSError as e:
        print(f"Couldn't connect to {target_ip}: {e}")
        return

    reason = run_send_loop(client, lambda: client.connected)
    if reason == "user_exit":
        client.leave()
        time.sleep(0.1)
    client.close()
    print(fmt_plain_status("Chat ended"))


def main():
    while True:
        print_banner()
        print(fmt_plain_status(f"This device: {get_identity()}"))
        role = choose_role()
        target_ip = ask_target_ip() if role == "join" else None

        while True:
            if role == "host":
                run_host_session()
            else:
                run_client_session(target_ip)

            action = ask_restart()
            if action == "q":
                print("Goodbye!")
                return
            if action == "m":
                break


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")

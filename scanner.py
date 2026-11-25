"""TCP connect() port scanner built on the Python standard library.

Scope and safety
----------------
* Only plain TCP connect scans are performed (a full three-way handshake).
  There is no stealth scanning, no exploitation and no flooding.
* Targets are restricted to loopback addresses, private (RFC 1918) networks and
  targets the user has explicitly registered as authorized.
* Port range, timeout and thread count are all capped.
"""
import errno
import ipaddress
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Probable services, derived ONLY from the port number (not from banners).
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Proxy / Alternative HTTP",
    27017: "MongoDB",
}

MAX_PORTS_PER_SCAN = 5000
MIN_TIMEOUT, MAX_TIMEOUT, DEFAULT_TIMEOUT = 0.1, 5.0, 1.0
MAX_WORKERS, DEFAULT_WORKERS = 200, 100

# "Connection refused" error numbers on Linux/macOS (111/61) and Windows (10061).
REFUSED_CODES = {errno.ECONNREFUSED, 111, 61, 10061}

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


class ScanError(Exception):
    """A problem with the scan request that should be shown to the user."""
    status = 400


class AuthorizationError(ScanError):
    status = 403


class BusyError(ScanError):
    status = 409


def probable_service(port):
    return COMMON_SERVICES.get(port, "Unknown")


# ------------------------------------------------------------ validation
def _to_int(value, label):
    if isinstance(value, bool) or value is None:
        raise ScanError(f"{label} is required and must be a whole number.")
    try:
        return int(str(value).strip())
    except ValueError:
        raise ScanError(f"{label} must be a whole number.")


def _to_float(value, label):
    if isinstance(value, bool) or value is None:
        raise ScanError(f"{label} must be a number.")
    try:
        number = float(str(value).strip())
    except ValueError:
        raise ScanError(f"{label} must be a number.")
    if number != number or number in (float("inf"), float("-inf")):
        raise ScanError(f"{label} must be a finite number.")
    return number


def parse_scan_request(data):
    """Validate the JSON body of POST /api/scan and return clean values."""
    target = data.get("target")
    if not isinstance(target, str) or not target.strip():
        raise ScanError("Target IP address or hostname is required.")

    start = _to_int(data.get("start_port"), "Starting port")
    end = _to_int(data.get("end_port"), "Ending port")
    if not (1 <= start <= 65535) or not (1 <= end <= 65535):
        raise ScanError("Ports must be between 1 and 65535.")
    if end < start:
        raise ScanError("Ending port must be greater than or equal to the starting port.")
    if end - start + 1 > MAX_PORTS_PER_SCAN:
        raise ScanError(f"A single scan may cover at most {MAX_PORTS_PER_SCAN} ports. Please narrow the range.")

    timeout = _to_float(data.get("timeout", DEFAULT_TIMEOUT), "Timeout")
    if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        raise ScanError(f"Timeout must be between {MIN_TIMEOUT} and {MAX_TIMEOUT} seconds.")

    workers = _to_int(data.get("workers", DEFAULT_WORKERS), "Threads")
    if not (1 <= workers <= MAX_WORKERS):
        raise ScanError(f"Threads must be between 1 and {MAX_WORKERS}.")

    return {"target": target.strip(), "start_port": start, "end_port": end,
            "timeout": round(timeout, 2), "workers": workers}


def resolve_target(raw):
    """Validate an IPv4 address or hostname and return (clean_target, ipv4_string)."""
    target = (raw or "").strip()
    if not target or len(target) > 253:
        raise ScanError("Target IP address or hostname is required.")

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None

    if ip is not None:
        if ip.version != 4:
            raise ScanError("Only IPv4 targets are supported in this version.")
        return target, str(ip)

    if re.fullmatch(r"[0-9.]+", target):
        raise ScanError("That is not a valid IPv4 address.")
    if not HOSTNAME_RE.match(target):
        raise ScanError("Invalid hostname. Use letters, digits, hyphens and dots only "
                        "(no URLs, spaces or special characters).")
    try:
        infos = socket.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"Could not resolve hostname '{target}'. Check the spelling and your network.")
    if not infos:
        raise ScanError(f"Hostname '{target}' has no IPv4 address.")
    return target, infos[0][4][0]


def validate_authorized_entry(raw):
    """Validate an entry for the authorized-targets list (IPv4, CIDR or hostname)."""
    value = (raw or "").strip().lower()
    if not value or len(value) > 253:
        raise ScanError("Enter an IPv4 address, CIDR range or hostname.")
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.version != 4:
            raise ScanError("Only IPv4 addresses and ranges are supported.")
        if net.prefixlen < 16:
            raise ScanError("Ranges larger than /16 are not allowed. Register a smaller range.")
        return str(net) if "/" in value else str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9./]+", value) or not HOSTNAME_RE.match(value):
        raise ScanError("That is not a valid IPv4 address, CIDR range or hostname.")
    return value


def check_authorization(target, ip_str, authorized_entries):
    """Raise AuthorizationError unless the target may be scanned. Returns a reason string."""
    ip = ipaddress.ip_address(ip_str)
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ScanError(f"{ip_str} is not a scannable unicast address.")
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private network"

    for entry in authorized_entries:
        entry = entry.lower()
        if entry == target.lower() or entry == ip_str:
            return "authorized target"
        try:
            if ip in ipaddress.ip_network(entry, strict=False):
                return "authorized range"
        except ValueError:
            continue
    raise AuthorizationError(
        f"{target} ({ip_str}) is a public address that is not on your authorized-targets list. "
        "Only scan systems you own or have written permission to test. If you do, add it under "
        "'Authorized targets' on the Port Scanner page first."
    )


# ----------------------------------------------------------- scan engine
def probe_port(ip, port, timeout):
    """Try one TCP connection. Returns (port, 'open' | 'closed' | 'filtered')."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((ip, port))
        if code == 0:
            return port, "open"
        if code in REFUSED_CODES:
            return port, "closed"
        return port, "filtered"
    except socket.timeout:
        return port, "filtered"
    except OSError:
        return port, "filtered"
    finally:
        sock.close()


class ScanJob:
    """In-memory state of one running scan (read by the progress endpoint)."""

    def __init__(self, scan_id, user_id, target, ip, start_port, end_port, timeout, workers):
        self.scan_id = scan_id
        self.user_id = user_id
        self.target = target
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.workers = workers
        self.total = end_port - start_port + 1
        self.cancel_event = threading.Event()
        self.outcome = "completed"
        self.duration = 0.0
        self.scanned = 0
        self.closed = 0
        self.filtered = 0
        self.open_ports = []
        self._lock = threading.Lock()

    def record(self, port, state):
        with self._lock:
            self.scanned += 1
            if state == "open":
                self.open_ports.append({"port": port, "service": probable_service(port)})
            elif state == "closed":
                self.closed += 1
            else:
                self.filtered += 1

    def snapshot(self):
        with self._lock:
            return {
                "scanned": self.scanned,
                "total": self.total,
                "closed": self.closed,
                "filtered": self.filtered,
                "open_ports": sorted(self.open_ports, key=lambda p: p["port"]),
            }


def run_scan(job):
    """Scan every port of the job using a bounded thread pool (blocking)."""
    started = time.perf_counter()
    executor = ThreadPoolExecutor(max_workers=job.workers)
    try:
        futures = [executor.submit(probe_port, job.ip, port, job.timeout)
                   for port in range(job.start_port, job.end_port + 1)]
        for future in as_completed(futures):
            if job.cancel_event.is_set():
                job.outcome = "cancelled"
                break
            port, state = future.result()
            job.record(port, state)
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
        job.duration = round(time.perf_counter() - started, 3)


_JOBS = {}
_JOBS_LOCK = threading.Lock()


def register_job(job):
    with _JOBS_LOCK:
        _JOBS[job.scan_id] = job


def get_job(scan_id):
    with _JOBS_LOCK:
        return _JOBS.get(scan_id)


def remove_job(scan_id):
    with _JOBS_LOCK:
        _JOBS.pop(scan_id, None)


def user_has_running_job(user_id):
    with _JOBS_LOCK:
        return any(j.user_id == user_id for j in _JOBS.values())

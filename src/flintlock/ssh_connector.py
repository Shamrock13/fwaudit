"""Live SSH connector — pull running configs from network devices."""
import os
import time
import uuid
import tempfile

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

RECV_TIMEOUT = 30    # seconds to wait for device output
RECV_CHUNK   = 65536


def _require_paramiko():
    if not PARAMIKO_AVAILABLE:
        raise RuntimeError(
            "Live SSH connection requires the 'paramiko' library. "
            "Install it with: pip install paramiko"
        )


def _read_until_idle(channel, timeout=RECV_TIMEOUT, idle_secs=1.5):
    """Read from channel until no data arrives for idle_secs, or timeout expires."""
    output = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(RECV_CHUNK)
            if not chunk:
                break
            output += chunk
        else:
            time.sleep(0.3)
            # If no data for idle_secs consecutively, assume done
            if not channel.recv_ready():
                time.sleep(idle_secs)
                if not channel.recv_ready():
                    break
    return output.decode("utf-8", errors="ignore")


def _make_client(host, port, username, password, timeout,
                  host_key_policy: str = "warn"):
    """Create and connect a Paramiko SSH client.

    *host_key_policy* controls how unknown host keys are handled:
      ``"strict"``   — RejectPolicy: refuse connections to hosts not in
                       known_hosts.  Most secure; requires pre-population of
                       ~/.ssh/known_hosts or the system known_hosts file.
      ``"warn"``     — WarningPolicy: log a warning and continue.  Balances
                       usability with visibility (default, replaces old insecure
                       AutoAddPolicy).
      ``"auto_add"`` — AutoAddPolicy: silently accept any host key.  Insecure
                       (MITM-vulnerable); available only for isolated lab use.
    """
    client = paramiko.SSHClient()
    # Load system + user known_hosts so strict/warn modes work with pre-approved keys.
    client.load_system_host_keys()
    try:
        client.load_host_keys(os.path.expanduser("~/.ssh/known_hosts"))
    except FileNotFoundError:
        pass
    _policy_map = {
        "strict":   paramiko.RejectPolicy,
        "warn":     paramiko.WarningPolicy,
        "auto_add": paramiko.AutoAddPolicy,
    }
    policy_cls = _policy_map.get(host_key_policy, paramiko.WarningPolicy)
    client.set_missing_host_key_policy(policy_cls())
    client.connect(
        host, port=port, username=username, password=password,
        timeout=timeout, look_for_keys=False, allow_agent=False,
    )
    return client


# ── Cisco ASA ─────────────────────────────────────────────────────────────────

def _pull_asa(host, port, username, password, timeout, host_key_policy="warn"):
    _require_paramiko()
    client = _make_client(host, port, username, password, timeout, host_key_policy)
    try:
        ch = client.invoke_shell()
        time.sleep(1)
        ch.recv(RECV_CHUNK)  # flush banner
        ch.send("terminal pager 0\n")
        time.sleep(0.5)
        ch.recv(RECV_CHUNK)
        ch.send("show running-config\n")
        return _read_until_idle(ch)
    finally:
        client.close()


# ── Fortinet ──────────────────────────────────────────────────────────────────

def _pull_fortinet(host, port, username, password, timeout, host_key_policy="warn"):
    _require_paramiko()
    client = _make_client(host, port, username, password, timeout, host_key_policy)
    try:
        ch = client.invoke_shell()
        time.sleep(1)
        ch.recv(RECV_CHUNK)
        ch.send("config global\n")
        time.sleep(0.5)
        ch.recv(RECV_CHUNK)
        ch.send("show full-configuration firewall policy\n")
        return _read_until_idle(ch, timeout=45)
    finally:
        client.close()


# ── Palo Alto Networks ────────────────────────────────────────────────────────

def _pull_paloalto(host, port, username, password, timeout, host_key_policy="warn"):
    """Pull running config via PA CLI SSH command."""
    _require_paramiko()
    client = _make_client(host, port, username, password, timeout, host_key_policy)
    try:
        stdin, stdout, stderr = client.exec_command(
            "show config running", timeout=timeout
        )
        # PA can take several seconds to dump the XML
        time.sleep(5)
        out = stdout.read()
        return out.decode("utf-8", errors="ignore")
    finally:
        client.close()


# ── Cisco FTD ─────────────────────────────────────────────────────────────────
# FTD LINA CLI accepts the same commands as ASA for pulling the running config.

def _pull_ftd(host, port, username, password, timeout, host_key_policy="warn"):
    """Pull FTD running config via LINA CLI (same as ASA)."""
    return _pull_asa(host, port, username, password, timeout, host_key_policy)


# ── Main entrypoint ───────────────────────────────────────────────────────────

_SUFFIXES = {"asa": ".txt", "ftd": ".txt", "fortinet": ".txt", "paloalto": ".xml"}
_PULLERS  = {
    "asa":      _pull_asa,
    "ftd":      _pull_ftd,
    "fortinet": _pull_fortinet,
    "paloalto": _pull_paloalto,
}


def connect_and_pull(vendor, host, port, username, password, timeout=30,
                     upload_folder=None, host_key_policy: str = "warn"):
    """
    Connect to a live device, pull its running config, and save to a temp file.

    Returns (temp_file_path, raw_content_str).
    Raises RuntimeError / paramiko exceptions on failure.
    """
    puller = _PULLERS.get(vendor)
    if puller is None:
        raise ValueError(f"Live SSH not supported for vendor: {vendor}")

    content = puller(host, int(port), username, password, int(timeout), host_key_policy)

    if not content or len(content.strip()) < 50:
        raise RuntimeError(
            "Device returned an empty or very short response. "
            "Check credentials and that the account has sufficient privileges."
        )

    suffix = _SUFFIXES[vendor]
    folder = upload_folder or tempfile.gettempdir()
    tmp_path = os.path.join(folder, f"flintlock_live_{uuid.uuid4().hex}{suffix}")
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(content)

    return tmp_path, content

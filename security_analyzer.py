"""Risk classification and recommendation engine.

An open port alone does NOT prove a vulnerability. The classifications below
describe the *exposure risk* of a service being reachable, and every level can
be changed by the user (Security Analysis page -> Risk classification rules).
"""
from scanner import probable_service

RISK_ORDER = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}
VALID_RISKS = ("HIGH", "MEDIUM", "LOW", "INFO")

DISCLAIMER = (
    "An open port alone does not prove a vulnerability. It shows that a service accepts connections. "
    "Whether that is a real security problem depends on the software version, its configuration, "
    "authentication and who can reach it. Services are listed as 'probable' because they are "
    "inferred from the port number only; no banner or protocol check is performed."
)

# default risk + explanation + mitigation, keyed by port number
KNOWLEDGE = {
    21: ("HIGH",
         "FTP sends usernames, passwords and files in clear text and is a frequent target of brute-force "
         "attacks and anonymous-access misconfigurations.",
         "Replace FTP with SFTP or FTPS, disable anonymous login and restrict access with firewall rules."),
    22: ("MEDIUM",
         "SSH gives encrypted remote administration but is a very common brute-force target when exposed "
         "to the whole network.",
         "Allow SSH only from trusted IP addresses, use key-based authentication, disable root and "
         "password login, and keep OpenSSH updated."),
    23: ("HIGH",
         "Telnet transmits everything, including passwords, unencrypted. Anyone on the network path can "
         "read or hijack the session.",
         "Disable Telnet and use SSH instead. Block port 23 at the firewall."),
    25: ("MEDIUM",
         "An SMTP server that is misconfigured can be abused as an open mail relay for spam or phishing "
         "and may leak information about valid users.",
         "Require authentication and TLS, disable open relay, and allow SMTP only for hosts that need it."),
    53: ("INFO",
         "DNS is expected on name servers, but misconfigured servers can act as open resolvers (used in "
         "amplification attacks) or allow zone transfers.",
         "Disable recursion for outside clients, restrict zone transfers, or close the port if this host "
         "is not a DNS server."),
    80: ("INFO",
         "A web server is reachable. Traffic on plain HTTP is not encrypted, so content and cookies can "
         "be intercepted.",
         "Redirect HTTP to HTTPS where appropriate, keep the web server patched and hide version banners."),
    110: ("MEDIUM",
          "POP3 normally sends mailbox credentials without encryption.",
          "Use POP3S (port 995) or STARTTLS, or disable POP3 if it is not needed."),
    143: ("MEDIUM",
          "IMAP normally sends mailbox credentials without encryption.",
          "Use IMAPS (port 993) or STARTTLS, or disable IMAP if it is not needed."),
    443: ("INFO",
          "An HTTPS web service is reachable. This is normal for web servers; its security depends on the "
          "TLS configuration and the application behind it.",
          "Use modern TLS versions, valid certificates and keep the application and server patched."),
    445: ("HIGH",
          "SMB file sharing has a long history of serious vulnerabilities and worm outbreaks and should "
          "not be reachable from untrusted networks.",
          "Block port 445 from untrusted networks, disable SMBv1 and apply operating-system updates."),
    3306: ("MEDIUM",
           "A MySQL database port is reachable over the network. Databases should normally only accept "
           "connections from the application server.",
           "Bind MySQL to localhost or a private interface, firewall port 3306 and require strong credentials."),
    3389: ("HIGH",
           "Remote Desktop exposed to the network is a leading entry point for brute-force and "
           "ransomware attacks.",
           "Restrict RDP to trusted IP addresses or a VPN, enable Network Level Authentication and MFA."),
    5432: ("MEDIUM",
           "A PostgreSQL database port is reachable over the network. Databases should normally only "
           "accept connections from the application server.",
           "Limit listen_addresses and pg_hba.conf to trusted hosts, firewall port 5432 and use strong credentials."),
    5900: ("HIGH",
           "VNC remote desktop often uses weak passwords and little or no encryption.",
           "Do not expose VNC directly; tunnel it through SSH or a VPN and require strong authentication."),
    6379: ("HIGH",
           "Redis frequently runs without authentication by default; an exposed instance can allow data "
           "theft or modification.",
           "Bind Redis to localhost, enable authentication (requirepass/ACLs) and firewall port 6379."),
    8080: ("LOW",
           "An alternative HTTP service or proxy is reachable. These are often development servers, "
           "admin consoles or proxies.",
           "Confirm the service is intended, protect admin interfaces with authentication and restrict access."),
    27017: ("MEDIUM",
            "A MongoDB database port is reachable over the network. Exposed instances without "
            "authentication have been widely compromised.",
            "Enable authentication, bind to a private interface and firewall port 27017."),
}

UNKNOWN_ENTRY = (
    "LOW",
    "No well-known service is associated with this port. It may be a legitimate custom application "
    "or something unexpected.",
    "Identify the process listening on this port, confirm it is required, and close or firewall it otherwise.",
)


def default_risk(port):
    return KNOWLEDGE.get(port, UNKNOWN_ENTRY)[0]


def analyze_port(port, overrides=None):
    """Return the full analysis record for one open port."""
    risk, explanation, mitigation = KNOWLEDGE.get(port, UNKNOWN_ENTRY)
    overridden = False
    if overrides and port in overrides and overrides[port] in VALID_RISKS:
        overridden = overrides[port] != risk
        risk = overrides[port]
    return {
        "port": port,
        "service": probable_service(port),
        "status": "open",
        "risk": risk,
        "risk_overridden": overridden,
        "explanation": explanation,
        "mitigation": mitigation,
    }


def summarize(ports):
    counts = {level: 0 for level in VALID_RISKS}
    for p in ports:
        counts[p["risk"]] = counts.get(p["risk"], 0) + 1
    overall = "NONE"
    for level in VALID_RISKS:
        if counts[level]:
            overall = level
            break
    return {"counts": counts, "overall": overall}


def generate_recommendations(ports):
    """Build recommendations from the ports that were actually found open."""
    by_port = {p["port"]: p for p in ports}
    recs = []

    def add(port_list, title, detail, fixed_priority=None):
        present = [by_port[x] for x in port_list if x in by_port]
        if not present:
            return
        priority = fixed_priority or max((p["risk"] for p in present), key=lambda r: RISK_ORDER[r])
        recs.append({"priority": priority, "title": title, "detail": detail,
                     "ports": sorted(p["port"] for p in present)})

    add([23], "Disable Telnet and use SSH",
        "Telnet is unencrypted. Turn the service off, remove the package if possible, and use SSH for "
        "remote administration.")
    add([21], "Replace FTP with SFTP or FTPS",
        "FTP exposes credentials in clear text. Move file transfers to SFTP (over SSH) or FTPS and "
        "disable anonymous access.")
    add([3389], "Restrict RDP to trusted IP addresses",
        "Do not expose Remote Desktop to the whole network. Allow it only through a VPN or from "
        "specific trusted addresses, and enable Network Level Authentication and multi-factor authentication.")
    add([445], "Block SMB from untrusted networks",
        "File sharing should only be reachable on the local network. Block port 445 at the firewall, "
        "disable SMBv1 and keep the system patched.")
    add([5900], "Protect or remove VNC access",
        "Tunnel VNC through SSH or a VPN, use strong passwords, or disable it if remote desktop is not required.")
    add([22], "Restrict SSH access using firewall rules",
        "Limit SSH to trusted source addresses, use key-based authentication, disable root login and "
        "consider a brute-force protection tool such as fail2ban.")
    add([3306, 5432, 6379, 27017], "Avoid exposing database ports publicly",
        "Databases should listen on localhost or a private network and accept connections only from "
        "application servers. Use firewall rules, strong credentials and TLS.")
    add([25], "Harden the SMTP service",
        "Require authentication and TLS, make sure the server is not an open relay, and restrict who can connect.")
    add([110, 143], "Use encrypted mail protocols",
        "Switch to POP3S/IMAPS (or require STARTTLS) so that mailbox passwords are not sent in clear text.")
    if 80 in by_port and 443 not in by_port:
        add([80], "Use HTTPS instead of unencrypted HTTP where appropriate",
            "Only plain HTTP was found. Install a TLS certificate, serve the site over HTTPS and redirect HTTP to it.")
    elif 80 in by_port and 443 in by_port:
        add([80, 443], "Redirect HTTP to HTTPS",
            "Both web ports are open. Redirect all HTTP requests to HTTPS and consider enabling HSTS.")
    add([8080], "Review the alternative HTTP / proxy service",
        "Confirm that the service on 8080 is intended, is not an open proxy or an unprotected admin console, "
        "and is restricted to the users who need it.")
    add([53], "Secure the DNS service",
        "Disable recursion for external clients, restrict zone transfers, or close port 53 if this host "
        "is not a DNS server.")

    unknown = [p for p in ports if p["port"] not in KNOWLEDGE]
    if unknown:
        add([p["port"] for p in unknown], "Identify and review unrecognised services",
            "Find out which application is listening on each unrecognised port and whether it is needed. "
            "Close or firewall anything that is not required.")

    if ports:
        add([p["port"] for p in ports], "Close unnecessary open ports",
            "Every listening service increases the attack surface. Stop and disable services that are not "
            "required for this system.", "MEDIUM")
        add([p["port"] for p in ports], "Apply firewall rules and network segmentation",
            "Use a default-deny firewall (host firewall and cloud security group), allow only the ports and "
            "source addresses that are needed, and keep databases and admin services in a private network segment.",
            "MEDIUM")
    else:
        recs.append({"priority": "INFO", "title": "No open ports detected in the scanned range",
                     "detail": "No service accepted a connection in this range. Ports reported as 'filtered' "
                               "may still be protected by a firewall rather than closed. Keep a default-deny "
                               "firewall policy and re-scan after configuration changes.",
                     "ports": []})

    recs.sort(key=lambda r: -RISK_ORDER[r["priority"]])
    return recs


def build_summary(scan, ports):
    """Plain-language final summary used on screen and in the PDF."""
    scanned = scan.get("total_scanned", 0)
    open_n = len(ports)
    counts = summarize(ports)["counts"]
    text = (f"The scan of {scan['target']} ({scan['resolved_ip']}) examined {scanned} port(s) in the range "
            f"{scan['start_port']}-{scan['end_port']} and found {open_n} open port(s). ")
    if open_n == 0:
        text += "No services accepted connections in the scanned range, which indicates a small exposed attack surface for these ports. "
    else:
        text += (f"Classification: {counts['HIGH']} high, {counts['MEDIUM']} medium, "
                 f"{counts['LOW']} low and {counts['INFO']} informational. ")
        if counts["HIGH"]:
            text += "High-risk exposures should be addressed first, starting with the recommendations marked HIGH. "
        elif counts["MEDIUM"]:
            text += "No high-risk ports were found, but the medium-risk services should be restricted to trusted hosts. "
        else:
            text += "Only low-risk or informational services were found. "
    if scan.get("status") == "cancelled":
        text += "Note: this scan was cancelled before every port was checked. "
    text += DISCLAIMER
    return text

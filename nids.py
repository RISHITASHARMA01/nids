#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP
from collections import defaultdict
import datetime, threading, time, argparse
from logger import NIDSLogger
from alerts import EmailAlerter

# ── Detection defaults ────────────────────────────────────────────────────────
# All three can be overridden via CLI flags (see main() below)

PORT_SCAN_THRESHOLD = 10   # unique ports seen before triggering an alert
TIME_WINDOW         = 5    # seconds to look back when counting ports
ALERT_COOLDOWN      = 60   # seconds before re-alerting on the same source IP

# ── State ─────────────────────────────────────────────────────────────────────

port_scan_tracker = defaultdict(lambda: defaultdict(set))
alerted_ips       = {}
logger  = NIDSLogger()
alerter = EmailAlerter()
lock    = threading.Lock()

# ── Severity ──────────────────────────────────────────────────────────────────

def get_severity(port_count):
    if port_count >= 50: return "CRITICAL"
    if port_count >= 25: return "HIGH"
    if port_count >= 10: return "MEDIUM"
    return "LOW"

# ── Detection ─────────────────────────────────────────────────────────────────

def is_on_cooldown(src_ip):
    if src_ip in alerted_ips:
        return (time.time() - alerted_ips[src_ip]) < ALERT_COOLDOWN
    return False

def cleanup_old_entries():
    while True:
        time.sleep(TIME_WINDOW)
        now = time.time()
        with lock:
            for ip in list(port_scan_tracker.keys()):
                for ts in list(port_scan_tracker[ip].keys()):
                    if ts < now - TIME_WINDOW:
                        del port_scan_tracker[ip][ts]
                if not port_scan_tracker[ip]:
                    del port_scan_tracker[ip]
            for ip in list(alerted_ips.keys()):
                if now - alerted_ips[ip] > ALERT_COOLDOWN:
                    del alerted_ips[ip]

def detect_port_scan(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP)): return
    src_ip   = packet[IP].src
    dst_port = packet[TCP].dport
    flags    = packet[TCP].flags
    now      = time.time()
    if "S" not in str(flags): return
    with lock:
        bucket = int(now // TIME_WINDOW) * TIME_WINDOW
        port_scan_tracker[src_ip][bucket].add(dst_port)
        all_ports = set()
        for ports in port_scan_tracker[src_ip].values():
            all_ports.update(ports)
        port_count = len(all_ports)
        if port_count >= PORT_SCAN_THRESHOLD and not is_on_cooldown(src_ip):
            severity = get_severity(port_count)
            trigger_alert(src_ip, port_count, all_ports, severity)
            alerted_ips[src_ip] = now

def trigger_alert(src_ip, port_count, ports, severity):
    timestamp = str(datetime.datetime.now())
    port_list = sorted(list(ports))[:20]
    alert = {
        "type": "PORT_SCAN", "severity": severity, "src_ip": src_ip,
        "port_count": port_count, "ports": port_list, "timestamp": timestamp,
        "message": f"Port scan from {src_ip} — {port_count} ports probed",
    }
    logger.log_alert(alert)
    alerter.send(
        f"[{severity}] Port Scan from {src_ip}",
        f"NIDS ALERT\nTime: {timestamp}\nSeverity: {severity}\nSource: {src_ip}\nPorts: {port_count}")
    color = "\033[91m" if severity in ("CRITICAL", "HIGH") else "\033[93m"
    reset = "\033[0m"
    print(f"\n{color}{'='*60}")
    print(f"  ALERT [{severity}] PORT SCAN DETECTED")
    print(f"  Source IP : {src_ip}")
    print(f"  Ports Hit : {port_count} unique ports")
    print(f"  Time      : {timestamp}")
    print(f"{'='*60}{reset}\n")

def process_packet(packet):
    try:
        logger.log_packet(packet)
        detect_port_scan(packet)
    except Exception as e:
        print(f"[!] Packet processing error: {e}")

# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="NIDS - Network Intrusion Detection System")
    parser.add_argument("-i", "--interface",   default="wlp0s20f3",          help="Network interface to monitor")
    parser.add_argument("-t", "--threshold",   default=PORT_SCAN_THRESHOLD,  type=int, help="Unique ports before alerting (default: 10)")
    parser.add_argument("-w", "--time-window", default=TIME_WINDOW,          type=int, help="Detection window in seconds (default: 5)")
    parser.add_argument("-c", "--cooldown",    default=ALERT_COOLDOWN,       type=int, help="Seconds before re-alerting same IP (default: 60)")
    args = parser.parse_args()

    global PORT_SCAN_THRESHOLD, TIME_WINDOW, ALERT_COOLDOWN
    PORT_SCAN_THRESHOLD = args.threshold
    TIME_WINDOW         = args.time_window
    ALERT_COOLDOWN      = args.cooldown

    threading.Thread(target=cleanup_old_entries, daemon=True).start()

    print("\n" + "="*60)
    print("   Network Intrusion Detection System (NIDS)")
    print("="*60)
    print(f"   Interface      : {args.interface}")
    print(f"   Threshold      : {PORT_SCAN_THRESHOLD} ports in {TIME_WINDOW}s")
    print(f"   Cooldown       : {ALERT_COOLDOWN}s between alerts per IP")
    print(f"   Email Alerts   : {'Enabled' if alerter.enabled else 'Disabled (configure .env)'}")
    print("="*60)
    print("  [*] Monitoring... Press Ctrl+C to stop\n")

    try:
        sniff(iface=args.interface, prn=process_packet, filter="tcp", store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        logger.print_summary()

if __name__ == "__main__":
    main()

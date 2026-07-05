#!/usr/bin/env python3
import sqlite3, json, datetime, os, atexit
from scapy.all import IP, TCP

DB_PATH    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "nids.db")
BATCH_SIZE = 50  # number of packets to buffer before committing to disk

class NIDSLogger:
    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")  # allows dashboard to read while nids.py writes
        self._pending = 0
        self._create_tables()
        atexit.register(self.flush)  # flush buffered packets even if nids.py crashes

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT, dst_ip TEXT, protocol TEXT,
            src_port INTEGER, dst_port INTEGER,
            flags TEXT, timestamp TEXT)""")
        cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT, severity TEXT, src_ip TEXT,
            port_count INTEGER, ports TEXT,
            message TEXT, timestamp TEXT)""")
        self.conn.commit()

    def log_packet(self, packet):
        if not packet.haslayer(IP): return
        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "OTHER"
        src_port = packet[TCP].sport if packet.haslayer(TCP) else 0
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0
        flags    = str(packet[TCP].flags) if packet.haslayer(TCP) else ""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO packets (src_ip,dst_ip,protocol,src_port,dst_port,flags,timestamp) VALUES (?,?,?,?,?,?,?)",
            (src_ip, dst_ip, protocol, src_port, dst_port, flags, str(datetime.datetime.now())))
        self._pending += 1
        if self._pending >= BATCH_SIZE:
            self.conn.commit()
            self._pending = 0

    def flush(self):
        """Commit any buffered packet writes. Call on shutdown."""
        if self._pending > 0:
            self.conn.commit()
            self._pending = 0

    def log_alert(self, alert: dict):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO alerts (type,severity,src_ip,port_count,ports,message,timestamp) VALUES (?,?,?,?,?,?,?)",
            (alert.get("type"), alert.get("severity"), alert.get("src_ip"),
             alert.get("port_count", 0), json.dumps(alert.get("ports", [])),
             alert.get("message"), alert.get("timestamp", str(datetime.datetime.now()))))
        self.conn.commit()  # alerts are always committed immediately — never batched

    def get_stats(self):
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM packets");   total_packets = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts");    total_alerts  = cur.fetchone()[0]
        cur.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
        by_severity = dict(cur.fetchall())
        cur.execute("SELECT src_ip, COUNT(*) as c FROM alerts GROUP BY src_ip ORDER BY c DESC LIMIT 5")
        top_attackers = cur.fetchall()
        return {"total_packets": total_packets, "total_alerts": total_alerts,
                "by_severity": by_severity, "top_attackers": top_attackers}

    def print_summary(self):
        self.flush()
        stats = self.get_stats()
        print("\n" + "="*60)
        print("   Session Summary")
        print("="*60)
        print(f"   Total Packets : {stats['total_packets']}")
        print(f"   Total Alerts  : {stats['total_alerts']}")
        for sev, count in stats["by_severity"].items():
            print(f"     {sev:<12} {count}")
        print("="*60)

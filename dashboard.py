#!/usr/bin/env python3
import streamlit as st
import pandas as pd
import sqlite3, json, os, time
import plotly.express as px

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "nids.db")

st.set_page_config(page_title="NIDS Dashboard", page_icon="shield", layout="wide")
st.markdown("""<style>
.critical { background:#3d0000; border-left:4px solid #ff0000; border-radius:6px; padding:12px; margin:6px 0; font-family:monospace; }
.high     { background:#2d1500; border-left:4px solid #ff6600; border-radius:6px; padding:12px; margin:6px 0; font-family:monospace; }
.medium   { background:#2d2500; border-left:4px solid #ffcc00; border-radius:6px; padding:12px; margin:6px 0; font-family:monospace; }
.low      { background:#002d00; border-left:4px solid #00cc00; border-radius:6px; padding:12px; margin:6px 0; font-family:monospace; }
</style>""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## NIDS Dashboard")
    auto_refresh    = st.checkbox("Auto Refresh (5s)", value=False)
    severity_filter = st.selectbox("Filter Alerts", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    st.divider()
    st.markdown("**Start NIDS:**")
    st.code("sudo python3 nids.py -i <interface>", language="bash")
    st.markdown("**Flags:** `-t` threshold · `-w` time window · `-c` cooldown")
    st.markdown("**Test with nmap:**")
    st.code("nmap -sT 127.0.0.1", language="bash")

st.title("Network Intrusion Detection System")
st.caption("Real-time port scan detection")
st.divider()

if not os.path.exists(DB_PATH):
    st.warning("No database found. Start NIDS first:")
    st.code("sudo python3 nids.py -i <interface>")
    st.stop()

# Cache the DB connection — Streamlit reruns the script on every interaction,
# so without caching this would open a new connection each time.
@st.cache_resource
def get_db():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

conn = get_db()

# ── Metrics ───────────────────────────────────────────────────────────────────

cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM packets"); total_packets = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM alerts");  total_alerts  = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'"); critical = cur.fetchone()[0]
cur.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'");     high     = cur.fetchone()[0]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Packets Monitored", f"{total_packets:,}")
c2.metric("Total Alerts",      total_alerts)
c3.metric("Critical",          critical)
c4.metric("High",              high)
st.divider()

# ── Charts ────────────────────────────────────────────────────────────────────

col1, col2 = st.columns(2)
with col1:
    st.subheader("Alerts by Severity")
    sev_df = pd.read_sql_query("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity", conn)
    if not sev_df.empty:
        color_map = {"CRITICAL": "#ff0000", "HIGH": "#ff6600", "MEDIUM": "#ffcc00", "LOW": "#00cc00"}
        fig = px.pie(sev_df, names="severity", values="count", hole=0.4,
                     color="severity", color_discrete_map=color_map)
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9", margin=dict(t=20,b=20,l=20,r=20))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No alerts yet.")

with col2:
    st.subheader("Top Attacker IPs")
    ip_df = pd.read_sql_query(
        "SELECT src_ip, COUNT(*) as alerts FROM alerts GROUP BY src_ip ORDER BY alerts DESC LIMIT 10", conn)
    if not ip_df.empty:
        fig2 = px.bar(ip_df, x="alerts", y="src_ip", orientation="h",
                      color="alerts", color_continuous_scale="Reds")
        fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="#c9d1d9",
                           showlegend=False, margin=dict(t=20,b=20,l=20,r=20),
                           yaxis=dict(autorange="reversed"))
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No data yet.")

st.divider()

# ── Live Alerts ───────────────────────────────────────────────────────────────

st.subheader("Live Alerts")
if severity_filter != "ALL":
    alerts_df = pd.read_sql_query(
        "SELECT * FROM alerts WHERE severity=? ORDER BY id DESC LIMIT 30",
        conn, params=(severity_filter,))
else:
    alerts_df = pd.read_sql_query("SELECT * FROM alerts ORDER BY id DESC LIMIT 30", conn)

if alerts_df.empty:
    st.success("No intrusions detected yet.")
else:
    for _, row in alerts_df.iterrows():
        sev   = (row["severity"] or "low").lower()
        ports = json.loads(row["ports"]) if row["ports"] else []
        st.markdown(
            f'<div class="{sev}"><b>{row["severity"]}</b> | PORT SCAN | '
            f'Source: <b>{row["src_ip"]}</b> | Ports Hit: <b>{row["port_count"]}</b><br>'
            f'Ports: {ports[:15]}<br>'
            f'<span style="color:#6e7681;">{row["timestamp"]}</span></div>',
            unsafe_allow_html=True)

st.divider()

# ── Recent Packets ────────────────────────────────────────────────────────────

st.subheader("Recent Packets")
pkt_df = pd.read_sql_query(
    "SELECT timestamp,src_ip,dst_ip,src_port,dst_port,flags FROM packets ORDER BY id DESC LIMIT 200", conn)
if not pkt_df.empty:
    pkt_df.columns = ["Timestamp", "Source IP", "Dest IP", "Src Port", "Dst Port", "Flags"]
    st.dataframe(pkt_df, use_container_width=True, height=350)
else:
    st.info("No packets yet.")

if auto_refresh:
    time.sleep(5)
    st.rerun()

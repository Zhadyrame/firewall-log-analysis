from __future__ import annotations

import argparse
from pathlib import Path
import ipaddress
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

try:
    from scapy.all import rdpcap, IP, TCP  # optional
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

ALLOW_COLOR = "#2ECC71"
DENY_COLOR = "#E74C3C"

RFC1918_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

HIGH_RISK_PORTS = {4444, 6667, 1080, 9050}
SENSITIVE_INBOUND = {22, 3389, 3306, 5432}


def is_rfc1918(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(str(ip))
        return any(a in n for n in RFC1918_NETS)
    except Exception:
        return False


def safe_read_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    required = {
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "action", "bytes_sent", "nat_src", "nat_dst"
    }
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"CSV missing columns: {sorted(missing)}")

    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["bytes_sent"] = pd.to_numeric(df["bytes_sent"], errors="coerce").fillna(0).astype(int)

    df["action"] = df["action"].astype(str).str.upper().str.strip()
    df["protocol"] = df["protocol"].astype(str).str.upper().str.strip()

    df["src_ip"] = df["src_ip"].astype(str).str.strip()
    df["dst_ip"] = df["dst_ip"].astype(str).str.strip()
    df["nat_src"] = df["nat_src"].astype(str).str.strip()
    df["nat_dst"] = df["nat_dst"].astype(str).str.strip()
    return df


def allow_deny_by_hour(df: pd.DataFrame) -> pd.DataFrame:
    tmp = df.copy()
    tmp["hour"] = tmp["timestamp"].dt.floor("h")
    pivot = tmp.pivot_table(index="hour", columns="action", values="src_ip", aggfunc="count", fill_value=0)
    for col in ["ALLOW", "DENY"]:
        if col not in pivot.columns:
            pivot[col] = 0
    return pivot[["ALLOW", "DENY"]].sort_index()


def allowed_high_risk_outbound(df: pd.DataFrame) -> pd.DataFrame:
    outbound = df[df["src_ip"].apply(is_rfc1918) & (~df["dst_ip"].apply(is_rfc1918))]
    risky = outbound[(outbound["action"] == "ALLOW") & (outbound["dst_port"].isin(list(HIGH_RISK_PORTS)))]
    cols = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "bytes_sent", "nat_src", "nat_dst"]
    return risky.sort_values("timestamp")[cols]


def high_bytes_sessions(df: pd.DataFrame, q: float = 0.995):
    thr = int(df["bytes_sent"].quantile(q)) if len(df) else 0
    big = df[df["bytes_sent"] >= thr].copy()
    cols = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_sent", "nat_src", "nat_dst"]
    return big.sort_values("bytes_sent", ascending=False)[cols], thr


def dnat_mappings(df: pd.DataFrame) -> pd.DataFrame:
    tmp = df.copy()

    def parse_ip_port(x: str):
        x = str(x).strip()
        if x in ("", "nan", "None"):
            return ("", np.nan)
        if ":" in x:
            ip, p = x.rsplit(":", 1)
            try:
                return (ip.strip(), int(p))
            except Exception:
                return (ip.strip(), np.nan)
        return (x, np.nan)

    dst_ip_port = tmp["dst_ip"].apply(lambda x: parse_ip_port(str(x)))
    nat_dst_ip_port = tmp["nat_dst"].apply(lambda x: parse_ip_port(str(x)))

    tmp["dst_ip_only"] = [a for a, _ in dst_ip_port]
    tmp["dst_port_only"] = tmp["dst_port"].astype("Int64")

    tmp["nat_dst_ip_only"] = [a for a, _ in nat_dst_ip_port]
    tmp["nat_dst_port_only"] = [b for _, b in nat_dst_ip_port]

    tmp["nat_dst_port_eff"] = tmp["nat_dst_port_only"].fillna(tmp["dst_port_only"]).astype("Int64")

    dnat = tmp[(tmp["nat_dst_ip_only"] != "") & (tmp["nat_dst_ip_only"] != tmp["dst_ip_only"])].copy()

    if dnat.empty:
        return pd.DataFrame(columns=[
            "external_ip", "external_port", "internal_ip", "internal_port",
            "sessions", "allowed", "denied"
        ])

    g = dnat.groupby(["dst_ip_only", "dst_port_only", "nat_dst_ip_only", "nat_dst_port_eff"])
    out = g.agg(
        sessions=("src_ip", "count"),
        allowed=("action", lambda s: int((s == "ALLOW").sum())),
        denied=("action", lambda s: int((s == "DENY").sum())),
    ).reset_index()

    out = out.rename(columns={
        "dst_ip_only": "external_ip",
        "dst_port_only": "external_port",
        "nat_dst_ip_only": "internal_ip",
        "nat_dst_port_eff": "internal_port",
    }).sort_values(["sessions"], ascending=False)

    return out


def dnat_sensitive_exposures(dnat_df: pd.DataFrame) -> pd.DataFrame:
    if dnat_df.empty:
        return dnat_df
    mask = dnat_df["external_port"].isin(list(SENSITIVE_INBOUND)) | dnat_df["internal_port"].isin(list(SENSITIVE_INBOUND))
    return dnat_df[mask].copy()


def snat_leaks(df: pd.DataFrame) -> pd.DataFrame:
    outbound = df[df["src_ip"].apply(is_rfc1918)]
    leak = outbound[(outbound["action"] == "ALLOW") & (outbound["dst_ip"].apply(is_rfc1918))]
    cols = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "nat_src", "nat_dst"]
    return leak.sort_values("timestamp")[cols]


def chart_allow_deny_per_hour(df: pd.DataFrame, outdir: Path) -> Path:
    pivot = allow_deny_by_hour(df)
    hours = pivot.index.astype("datetime64[ns]")
    allow = pivot["ALLOW"].values
    deny = pivot["DENY"].values

    plt.figure(figsize=(10, 4.8))
    plt.bar(hours, allow, label="ALLOW", color=ALLOW_COLOR)
    plt.bar(hours, deny, bottom=allow, label="DENY", color=DENY_COLOR)
    plt.title("ALLOW vs DENY Sessions per Hour")
    plt.xlabel("Hour")
    plt.ylabel("Session count")
    plt.legend()
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()

    out = outdir / "chart1_allow_deny_per_hour.png"
    plt.savefig(out, dpi=200)
    plt.close()
    return out


def chart_top_ports_split(df: pd.DataFrame, outdir: Path, top_n: int = 15) -> Path:
    tmp = df.copy()
    top_ports_list = tmp["dst_port"].value_counts().head(top_n).index.tolist()
    tmp = tmp[tmp["dst_port"].isin(top_ports_list)]
    g = tmp.groupby(["dst_port", "action"]).size().unstack(fill_value=0)
    for col in ["ALLOW", "DENY"]:
        if col not in g.columns:
            g[col] = 0
    g = g[["ALLOW", "DENY"]].sort_values("ALLOW", ascending=False)

    ports = g.index.astype(int).astype(str).tolist()
    allow = g["ALLOW"].values
    deny = g["DENY"].values

    plt.figure(figsize=(10, 6))
    y = np.arange(len(ports))
    plt.barh(y, allow, label="ALLOW", color=ALLOW_COLOR)
    plt.barh(y, deny, left=allow, label="DENY", color=DENY_COLOR)
    plt.yticks(y, ports)
    plt.gca().invert_yaxis()
    plt.title(f"Top {top_n} Destination Ports (split by action)")
    plt.xlabel("Session count")
    plt.ylabel("Destination port")
    plt.legend()
    plt.tight_layout()

    out = outdir / "chart2_top_ports_split_by_action.png"
    plt.savefig(out, dpi=200)
    plt.close()
    return out


def chart_heatmap(df: pd.DataFrame, outdir: Path, top_k: int = 10) -> Path:
    top_src = df["src_ip"].value_counts().head(top_k).index.tolist()
    top_port = df["dst_port"].value_counts().head(top_k).index.tolist()
    sub = df[df["src_ip"].isin(top_src) & df["dst_port"].isin(top_port)]
    mat = sub.groupby(["src_ip", "dst_port"]).size().unstack(fill_value=0).reindex(index=top_src, columns=top_port)

    plt.figure(figsize=(10, 5.5))
    plt.imshow(mat.values, aspect="auto")
    plt.colorbar(label="Session count")
    plt.yticks(np.arange(len(mat.index)), mat.index)
    plt.xticks(np.arange(len(mat.columns)), [str(int(c)) for c in mat.columns], rotation=45, ha="right")
    plt.title("Heatmap: Top 10 Source IPs vs Top 10 Destination Ports")
    plt.xlabel("Destination port")
    plt.ylabel("Source IP")
    plt.tight_layout()

    out = outdir / "chart3_heatmap_top_src_vs_ports.png"
    plt.savefig(out, dpi=200)
    plt.close()
    return out


def make_table_from_records(title: str, records: list[dict], max_rows: int = 8) -> list:
    elems = []
    styles = getSampleStyleSheet()
    elems.append(Paragraph(f"<b>{title}</b>", styles["Heading4"]))
    if not records:
        elems.append(Paragraph("No data.", styles["BodyText"]))
        elems.append(Spacer(1, 8))
        return elems

    keys = list(records[0].keys())
    data = [keys] + [[str(r.get(k, "")) for k in keys] for r in records[:max_rows]]

    t = Table(data, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(t)
    elems.append(Spacer(1, 10))
    return elems


def generate_report_pdf(out_pdf: Path, df: pd.DataFrame, chart_paths: list[Path]):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(out_pdf), pagesize=A4, topMargin=28, bottomMargin=28, leftMargin=34, rightMargin=34)
    elems = []

    t0, t1 = df["timestamp"].min(), df["timestamp"].max()
    allow_count = int((df["action"] == "ALLOW").sum())
    deny_count = int((df["action"] == "DENY").sum())

    risky = allowed_high_risk_outbound(df).head(10).to_dict(orient="records")
    big, thr = high_bytes_sessions(df, 0.995)
    big_rows = big.head(10).to_dict(orient="records")

    dnat = dnat_mappings(df)
    dnat_sens = dnat_sensitive_exposures(dnat)
    leaks = snat_leaks(df)

    top_deny = df[df["action"] == "DENY"]["src_ip"].value_counts().head(10).rename_axis("src_ip").reset_index(name="deny_sessions")
    top_deny_rows = top_deny.to_dict(orient="records")

    elems.append(Paragraph("<b>Firewall Audit Report — Laboratory Work 2</b>", styles["Title"]))
    elems.append(Paragraph(
        f"Dataset window: <b>{t0}</b> to <b>{t1}</b> | Total sessions: <b>{len(df)}</b> "
        f"(ALLOW: <b>{allow_count}</b>, DENY: <b>{deny_count}</b>)",
        styles["BodyText"]
    ))
    elems.append(Spacer(1, 10))

    elems.append(Paragraph("<b>1) Was the firewall migration performed securely?</b>", styles["Heading2"]))
    elems.append(Paragraph(
        f"Evidence suggests issues post-migration: ALLOW on high-risk outbound ports (4444/6667/1080/9050) "
        f"and DNAT exposures of sensitive services (SSH/RDP/DB).",
        styles["BodyText"]
    ))
    elems.append(Spacer(1, 8))

    elems.append(Paragraph("<b>2) What type of issue was identified?</b>", styles["Heading2"]))
    elems.append(Paragraph(
        "Firewall misconfiguration (overly permissive outbound) and unsafe DNAT port-forwarding to internal services.",
        styles["BodyText"]
    ))
    elems.append(Spacer(1, 8))

    elems.append(Paragraph("<b>3) Which internal assets are at risk?</b>", styles["Heading2"]))
    elems.extend(make_table_from_records("Sensitive DNAT exposures (external → internal)", dnat_sens.head(10).to_dict(orient="records"), 8))
    elems.extend(make_table_from_records("Allowed outbound on high-risk ports", risky, 8))
    elems.append(Paragraph("<b>Potential data exfiltration indicator</b>", styles["Heading3"]))
    elems.append(Paragraph(f"High bytes_sent sessions (>= {thr:,} bytes):", styles["BodyText"]))
    elems.extend(make_table_from_records("Top high-bytes sessions", big_rows, 6))

    elems.append(Paragraph("<b>4) What should the company do next?</b>", styles["Heading2"]))
    elems.append(Paragraph(
        "1) Remove/restrict unsafe DNAT; allowlist sources.\n"
        "2) Default-deny outbound; block non-standard ports.\n"
        "3) Ensure stateful rules (ESTABLISHED/RELATED).\n"
        "4) Enable full logging on ALLOW+DENY and alert on new NAT mappings.\n"
        "5) Enforce MFA/VPN for any remote admin access.",
        styles["BodyText"]
    ))

    elems.append(PageBreak())
    elems.append(Paragraph("<b>Appendix: Evidence tables</b>", styles["Heading2"]))
    elems.extend(make_table_from_records("Top sources by DENY events", top_deny_rows, 10))
    elems.extend(make_table_from_records("All DNAT mappings (top)", dnat.head(10).to_dict(orient="records"), 10))
    elems.extend(make_table_from_records("SNAT/Routing leaks (RFC1918 destination)", leaks.head(10).to_dict(orient="records"), 10))

    elems.append(Paragraph("<b>Charts</b>", styles["Heading2"]))
    for p in chart_paths:
        if p.exists():
            elems.append(Paragraph(p.name, styles["BodyText"]))
            elems.append(Image(str(p), width=500, height=280))
            elems.append(Spacer(1, 10))

    doc.build(elems)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="firewall_traffic.csv", help="Path to firewall_traffic.csv")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise SystemExit(f"CSV not found: {csv_path}")

    df = safe_read_csv(csv_path)

    outdir = Path("charts")
    outdir.mkdir(exist_ok=True)

    c1 = chart_allow_deny_per_hour(df, outdir)
    c2 = chart_top_ports_split(df, outdir, top_n=15)
    c3 = chart_heatmap(df, outdir, top_k=10)

    out_pdf = Path("report.pdf")
    generate_report_pdf(out_pdf, df, [c1, c2, c3])

    print("Done ")
    print("Charts:", c1, c2, c3)
    print("Report:", out_pdf.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
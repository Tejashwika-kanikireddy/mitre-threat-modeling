# streamlit_app.py
import streamlit as st
import spacy
nlp = spacy.load("en_core_web_sm")
import json
import pandas as pd
from datetime import datetime
import re
import io
import os
import glob

# ---------------------------
# PAGE CONFIG
# ---------------------------
st.set_page_config(page_title="Automated Threat Modeling (Core)", layout="wide")
st.title("Automated Threat Modeling Tool — Core (MITRE + Agile + AI)")
st.markdown("Minimal version: paste sprint backlog items → AI extracts keywords → map to MITRE → generate security user stories → export CSV / Jira CSV.")

# ---------------------------
# CVSS-like severity scoring (must be defined before use)
# ---------------------------
SEVERITY_SCORES = {"High": 9.0, "Medium": 6.0, "Low": 3.0}

# ---------------------------
# Persistence folder (optional)
# ---------------------------
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ---------------------------
# Default / base MITRE mapping (can be extended by upload)
# Keep this small; upload mitre_full.json to expand.
# ---------------------------
MITRE_MAP = {
    "login": [{"id": "T1110", "name": "Brute Force", "severity": "High", "notes": "Rate-limit login attempts, enable MFA"}],
    "password": [{"id": "T1003", "name": "Credential Dumping", "severity": "High", "notes": "Hash and salt passwords"}],
    "api": [{"id": "T1190", "name": "Exploit Public-Facing Application", "severity": "High", "notes": "Validate inputs, enforce rate limits"}],
    "upload": [{"id": "T1204", "name": "Malicious File Upload", "severity": "Medium", "notes": "Scan uploaded files, validate file type"}],
    "database": [{"id": "T1190", "name": "SQL Injection", "severity": "High", "notes": "Use prepared statements / ORM"}],
    "token": [{"id": "T1552", "name": "Token Exposure", "severity": "High", "notes": "Rotate tokens, short expiry"}],
    "admin": [{"id": "T1078", "name": "Valid Accounts", "severity": "High", "notes": "Harden admin access and enable MFA"}]
}

# ---------------------------
# Sidebar settings
# ---------------------------
st.sidebar.header("Agile Settings & MITRE Mapping")
upload_map = st.sidebar.file_uploader("Upload Additional MITRE Mapping JSON (optional)", type=["json"])
if upload_map:
    try:
        extra = json.load(upload_map)
        MITRE_MAP.update(extra)
        st.sidebar.success("MITRE mapping updated.")
    except Exception as e:
        st.sidebar.error("Invalid JSON: " + str(e))

auto_sprint = st.sidebar.checkbox("Auto-generate Sprint Number", value=True)

# helper to load history to compute max sprint
def load_history_max_sprint():
    csvs = sorted(glob.glob(os.path.join(REPORTS_DIR, "sprint_*.csv")))
    max_s = 0
    for f in csvs:
        try:
            d = pd.read_csv(f)
            if "sprint" in d.columns:
                ms = int(d["sprint"].max())
                if ms > max_s:
                    max_s = ms
        except Exception:
            continue
    return max_s

max_sprint = load_history_max_sprint()
if auto_sprint:
    sprint_no = max_sprint + 1
    st.sidebar.markdown(f"**Auto Sprint:** Next → **{sprint_no}**")
else:
    sprint_no = st.sidebar.number_input("Sprint Number (manual)", value=(max_sprint + 1), min_value=1)

assignee = st.sidebar.text_input("Assignee (optional)", value="Team")

# ---------------------------
# Helper functions
# ---------------------------
def extract_keywords(text):
    """
    Hybrid extraction: spaCy NER + rule-based MITRE keyword matching.
    Returns sorted list of found keywords/entities (lowercased).
    """
    doc = nlp(text)
    found = set()
    # add named entities and noun chunks (useful)
    for ent in doc.ents:
        found.add(ent.text.lower())
    # rule-based: check MITRE_MAP keys
    lowered = text.lower()
    for kw in MITRE_MAP.keys():
        if re.search(rf"\b{re.escape(kw)}\b", lowered):
            found.add(kw)
    return sorted(found)

def gen_security_story(keyword, technique, mitre_id, severity):
    templates = {
        "High": "As a system, I must implement {notes} to mitigate {technique} ({mitre_id}) risk for '{keyword}'.",
        "Medium": "As a system, I should apply {notes} to reduce {technique} ({mitre_id}) risk for '{keyword}'.",
        "Low": "Consider controls for {technique} ({mitre_id}) related to '{keyword}'."
    }
    mitigation = "recommended security controls"
    for entry in MITRE_MAP.get(keyword, []):
        if entry.get("id") == mitre_id:
            mitigation = entry.get("notes", mitigation)
    return templates.get(severity, templates["Low"]).format(notes=mitigation, technique=technique, mitre_id=mitre_id, keyword=keyword)

def create_jira_row(threat):
    priority_map = {"High": "Highest", "Medium": "High", "Low": "Medium"}
    return {
        "Summary": threat["security_user_story"],
        "Description": (
            f"Detected Keyword: {threat['keyword']}\n"
            f"MITRE Technique: {threat['technique']} ({threat['mitre_id']})\n"
            f"Severity: {threat['severity']}\n"
            f"Recommendation: {threat['recommendation']}\n"
            f"Original Story: {threat['story']}"
        ),
        "Issue Type": "Story",
        "Priority": priority_map.get(threat["severity"], "Medium"),
        "Sprint": threat["sprint"],
        "Assignee": threat["assignee"]
    }

def persist_sprint(df, sprint_no):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = os.path.join(REPORTS_DIR, f"sprint_{sprint_no}_{ts}.csv")
    df.to_csv(fname, index=False)
    return fname

# ---------------------------
# Input area
# ---------------------------
st.subheader("1) Paste Sprint Backlog Items / User Stories (one per line)")
stories_text = st.text_area("Paste user stories here:", height=220, placeholder="As a user, I want to login with email and password so I can access my dashboard.")
if not stories_text.strip():
    st.info("Please paste at least one user story to begin.")
    st.stop()

stories = [s.strip() for s in stories_text.splitlines() if s.strip()]

# ---------------------------
# Extraction display
# ---------------------------
st.subheader("2) Extracted Elements (from pasted sprint items)")
extracted_rows = []
for idx, s in enumerate(stories, start=1):
    found = extract_keywords(s)
    extracted_rows.append({"sprint": int(sprint_no), "story_id": idx, "story": s, "keywords": ", ".join(found) if found else "(none)"})
extracted_df = pd.DataFrame(extracted_rows)
st.dataframe(extracted_df, use_container_width=True)

# ---------------------------
# MITRE mapping & security user story generation
# ---------------------------
st.subheader("3) MITRE Mapping → Threats + Generated Security User Stories")
threat_rows = []
for r in extracted_rows:
    kws = [k.strip() for k in r["keywords"].split(",") if k.strip() and k.strip() != "(none)"]
    if not kws:
        threat_rows.append({
            "sprint": r["sprint"],
            "story_id": r["story_id"],
            "story": r["story"],
            "keyword": "(none)",
            "mitre_id": "(none)",
            "technique": "(none)",
            "severity": "Low",
            "score": SEVERITY_SCORES["Low"],
            "recommendation": "Manual review",
            "security_user_story": "Manual security review required",
            "assignee": assignee
        })
        continue
    for kw in kws:
        mappings = MITRE_MAP.get(kw, [])
        if mappings:
            for m in mappings:
                sec_story = gen_security_story(kw, m.get("name", "(unknown)"), m.get("id", "(unknown)"), m.get("severity", "Medium"))
                threat_rows.append({
                    "sprint": r["sprint"],
                    "story_id": r["story_id"],
                    "story": r["story"],
                    "keyword": kw,
                    "mitre_id": m.get("id", ""),
                    "technique": m.get("name", ""),
                    "severity": m.get("severity", "Medium"),
                    "score": SEVERITY_SCORES.get(m.get("severity", "Medium"), 0),
                    "recommendation": m.get("notes", ""),
                    "security_user_story": sec_story,
                    "assignee": assignee
                })
        else:
            # unknown keyword found by spaCy or entity
            sec_story = gen_security_story(kw, "(unknown)", "(unknown)", "Medium")
            threat_rows.append({
                "sprint": r["sprint"],
                "story_id": r["story_id"],
                "story": r["story"],
                "keyword": kw,
                "mitre_id": "(unknown)",
                "technique": "(unknown)",
                "severity": "Medium",
                "score": SEVERITY_SCORES["Medium"],
                "recommendation": "Extend mapping JSON",
                "security_user_story": sec_story,
                "assignee": assignee
            })

threat_df = pd.DataFrame(threat_rows)
if threat_df.empty:
    st.warning("No threats detected. Try different user stories or upload a mapping JSON.")
else:
    threat_df = threat_df.sort_values(["score", "story_id"], ascending=[False, True])
    display_cols = ["sprint", "story_id", "keyword", "mitre_id", "technique", "severity", "score", "security_user_story", "assignee"]
    st.dataframe(threat_df[display_cols], use_container_width=True)

# ---------------------------
# Save sprint report (optional)
# ---------------------------
if st.button("Save Sprint Report (persist CSV to ./reports/)"):
    if not threat_df.empty:
        fname = persist_sprint(threat_df, sprint_no)
        st.success(f"Sprint report saved to: {fname}")
    else:
        st.warning("Nothing to save.")

# ---------------------------
# Exports: Sprint CSV and Jira CSV
# ---------------------------
st.subheader("4) Export Sprint Threat Report")
csv_buffer = io.StringIO()
if not threat_df.empty:
    threat_df.to_csv(csv_buffer, index=False)
    st.download_button("Download Sprint Threat Report (CSV)", data=csv_buffer.getvalue().encode(),
                       file_name=f"sprint_{sprint_no}_threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
else:
    st.info("No threat report to download.")

st.subheader("5) Export Jira-Ready CSV")
if not threat_df.empty:
    jira_rows = [create_jira_row(t) for _, t in threat_df.iterrows()]
    jira_df = pd.DataFrame(jira_rows)
    jira_buffer = io.StringIO()
    jira_df.to_csv(jira_buffer, index=False)
    st.download_button("Download Jira-Ready CSV", data=jira_buffer.getvalue().encode(),
                       file_name=f"jira_security_stories_sprint_{sprint_no}.csv")
else:
    st.info("No Jira CSV to download.")

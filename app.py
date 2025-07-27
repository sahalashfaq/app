import streamlit as st
import pandas as pd
import re
import dns.resolver
import smtplib
import requests
import asyncio
import time
from email_validator import validate_email, EmailNotValidError
import io

# Load CSS
def load_css():
    try:
        with open("style.css") as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except:
        st.warning("No CSS loaded.")

load_css()

st.set_page_config(page_title="Email Validator Pro", layout="wide")
st.title("📩 Fast Email Validator")
st.write("Upload a CSV with an 'Email' column. The system will validate and show progress in real time.")

# Disposable domain loader
@st.cache_data
def fetch_disposable_domains():
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
    r = requests.get(url)
    return r.text.splitlines() if r.status_code == 200 else []

DISPOSABLE_DOMAINS = fetch_disposable_domains()
FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]

# Validation functions
def validate_syntax(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

def validate_domain(email):
    domain = email.split('@')[-1]
    try:
        dns.resolver.resolve(domain, 'MX')
        return True
    except:
        return False

def validate_mailbox(email):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        with smtplib.SMTP(mx_record, timeout=5) as server:
            server.helo("example.com")
            server.mail("test@example.com")
            code, _ = server.rcpt(email)
            return code == 250
    except:
        return False

def is_disposable(email):
    return email.split('@')[-1] in DISPOSABLE_DOMAINS

def is_free_email(email):
    return email.split('@')[-1] in FREE_EMAIL_DOMAINS

def is_catch_all(email):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx = str(mx_records[0].exchange)
        with smtplib.SMTP(mx, timeout=5) as server:
            server.helo("example.com")
            server.mail("test@example.com")
            code, _ = server.rcpt(f"randomaddress1234@{domain}")
            return code == 250
    except:
        return False

def get_status(syntax, domain, mailbox, catch_all):
    if not syntax or not domain:
        return "Not Deliverable"
    if mailbox and catch_all:
        return "Risky"
    if mailbox:
        return "Deliverable"
    return "Not Deliverable"

# Async validation function
async def validate_async(email):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: validate_email_address(email))

def validate_email_address(email):
    syntax = validate_syntax(email)
    if not syntax:
        return {"Email": email, "Deliverability": "Not Deliverable"}

    domain = validate_domain(email)
    if not domain:
        return {"Email": email, "Deliverability": "Not Deliverable"}

    mailbox = validate_mailbox(email)
    disposable = is_disposable(email)
    free = is_free_email(email)
    catch_all = is_catch_all(email)
    status = get_status(syntax, domain, mailbox, catch_all)

    return {
        "Email": email,
        "Syntax Valid": syntax,
        "Domain Valid": domain,
        "Mailbox Exists": mailbox,
        "Disposable Email": disposable,
        "Free Email": free,
        "Catch-All Domain": catch_all,
        "Deliverability": status
    }

# CSV Processor
async def process_csv(file):
    df = pd.read_csv(file)
    if 'Email' not in df.columns:
        st.error("CSV file must have an 'Email' column.")
        return

    emails = df["Email"].dropna().unique()
    total = len(emails)
    valid_count, invalid_count = 0, 0
    start_time = time.time()

    st.info(f"🔍 Total Emails to Process: {total}")
    progress = st.progress(0)
    status_box = st.empty()
    result = []

    for i, email in enumerate(emails):
        result.append(await validate_async(email))

        if result[-1]['Deliverability'] == "Deliverable":
            valid_count += 1
        else:
            invalid_count += 1

        elapsed = time.time() - start_time
        speed = (i + 1) / elapsed if elapsed > 0 else 0
        remaining = total - (i + 1)
        est_time = int(remaining / speed) if speed > 0 else 0

        status_box.markdown(f"""
        **Progress:** {i+1}/{total}  
        ✅ Valid: {valid_count}  
        ❌ Invalid: {invalid_count}  
        ⏳ Remaining: {remaining}  
        🚀 Speed: {speed:.2f} emails/sec  
        ⏱ Estimated Time Left: {est_time} sec
        """)

        progress.progress((i + 1) / total)

    final_df = pd.DataFrame(result)
    full = pd.merge(df, final_df, on="Email", how="left")

    buffer = io.StringIO()
    full.to_csv(buffer, index=False)
    buffer.seek(0)
    st.session_state.output_csv = buffer.getvalue()
    st.session_state.ready = True

# File upload
uploaded = st.file_uploader("Upload CSV", type=["csv"])

if uploaded and 'ready' not in st.session_state:
    asyncio.run(process_csv(uploaded))

# Download
if st.session_state.get("ready"):
    st.success("✅ Processing Complete!")
    st.download_button(
        "📥 Download Results CSV",
        st.session_state.output_csv,
        file_name="validated_results.csv",
        mime="text/csv"
    )
    if st.button("🔄 Validate Another File"):
        st.session_state.clear()
        st.experimental_rerun()

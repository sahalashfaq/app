import streamlit as st
import pandas as pd
import re
import dns.resolver
import smtplib
import requests
from email_validator import validate_email, EmailNotValidError
from tqdm import tqdm  # Progress bar
import io

# Load CSS
def load_css():
    try:
        with open("style.css") as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except:
        st.warning("No CSS loaded.")

load_css()

# Set page title and layout
st.set_page_config(page_title="Email Validator", layout="wide")
st.write("Upload a CSV file with an 'Email' column to validate email addresses.")

# Initialize session state
if 'file_processed' not in st.session_state:
    st.session_state.file_processed = False
if 'download_ready' not in st.session_state:
    st.session_state.download_ready = False

# Fetch disposable email domains from GitHub
def fetch_disposable_domains():
    url = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf"
    response = requests.get(url)
    return response.text.splitlines() if response.status_code == 200 else []

# Lists for disposable and free email domains
DISPOSABLE_DOMAINS = fetch_disposable_domains()
FREE_EMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]

# Validate email syntax
def validate_syntax(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

# Validate domain MX records
def validate_domain(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return len(mx_records) > 0
    except:
        return False

# Validate mailbox existence using SMTP
def validate_mailbox(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        with smtplib.SMTP(mx_record, timeout=10) as server:
            server.helo('example.com')
            server.mail('test@example.com')
            code, _ = server.rcpt(email)
            return code == 250
    except:
        return False

# Check if email is disposable
def is_disposable_email(email):
    domain = email.split('@')[1]
    return domain in DISPOSABLE_DOMAINS

# Check if email is from a free provider
def is_free_email(email):
    domain = email.split('@')[1]
    return domain in FREE_EMAIL_DOMAINS

# Check if domain is a catch-all mail exchanger
def is_catch_all_domain(email):
    domain = email.split('@')[1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(mx_records[0].exchange)
        with smtplib.SMTP(mx_record, timeout=10) as server:
            server.helo('example.com')
            server.mail('test@example.com')
            code, _ = server.rcpt(f'nonexistent@{domain}')
            return code == 250
    except:
        return False

# Determine email deliverability based on logic
def get_deliverability_status(syntax_valid, domain_valid, mailbox_exists, is_catch_all):
    if not syntax_valid or not domain_valid:
        return "Not Deliverable"
    if mailbox_exists and is_catch_all:
        return "Risky"
    if mailbox_exists:
        return "Deliverable"
    return "Not Deliverable"

# Validate an email address
def validate_email_address(email):
    syntax_valid = validate_syntax(email)
    if not syntax_valid:
        return {"Email": email, "Deliverability": "Not Deliverable"}

    domain_valid = validate_domain(email)
    if not domain_valid:
        return {"Email": email, "Deliverability": "Not Deliverable"}

    mailbox_exists = validate_mailbox(email)
    is_disposable = is_disposable_email(email)
    is_free = is_free_email(email)
    is_catch_all = is_catch_all_domain(email)
    deliverability_status = get_deliverability_status(syntax_valid, domain_valid, mailbox_exists, is_catch_all)

    return {
        "Email": email,
        "Syntax Valid": syntax_valid,
        "Domain Valid": domain_valid,
        "Mailbox Exists": mailbox_exists,
        "Disposable Email": is_disposable,
        "Free Email": is_free,
        "Catch-All Domain": is_catch_all,
        "Deliverability": deliverability_status
    }

# Process CSV file with progress bar
def process_csv(uploaded_file):
    # Read the uploaded file into a DataFrame
    df = pd.read_csv(uploaded_file)

    if "Email" not in df.columns:
        st.error("CSV file must have an 'Email' column")
        return

    results = []
    total_emails = len(df["Email"].dropna())

    st.write(f"Processing {total_emails} emails...")

    # Use tqdm for progress bar with email count
    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, email in enumerate(tqdm(df["Email"].dropna(), desc="Validating Emails", unit="email", total=total_emails)):
        results.append(validate_email_address(email))
        progress_bar.progress((i + 1) / total_emails)
        status_text.text(f"Processed {i + 1} of {total_emails} emails")

    # Convert results to DataFrame
    result_df = pd.DataFrame(results)
    df = pd.concat([df, result_df.drop(columns=["Email"])], axis=1)

    # Save output file to a buffer
    output_buffer = io.StringIO()
    df.to_csv(output_buffer, index=False)
    output_buffer.seek(0)  # Reset buffer position to the beginning

    # Store the output in session state
    st.session_state.output_buffer = output_buffer.getvalue()
    st.session_state.file_processed = True
    st.session_state.download_ready = True

# Streamlit file upload
uploaded_file = st.file_uploader("",type=["csv"])

if uploaded_file is not None and not st.session_state.file_processed:
    process_csv(uploaded_file)

# Display download button if processing is complete
if st.session_state.download_ready:
    st.success("Validation complete! Click below to download the validated CSV file.")
    st.download_button(
        label="Download Validated CSV",
        data=st.session_state.output_buffer,
        file_name="validated_emails.csv",
        mime="text/csv"
    )
    if st.button("Validate Another File"):
        st.session_state.file_processed = False
        st.session_state.download_ready = False
        st.experimental_rerun()

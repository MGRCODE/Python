import requests
import json
import streamlit as st
import pandas as pd

repo_url = f"https://{st.secrets['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']}@github.com/your-username/mgr_ai.git"

# Function to check a single IP using AbuseIPDB
def abuseipddb_ioc_checker(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    return response.json()

# Function to check multiple IPs using AbuseIPDB
def bulk_abuseipddb_ioc_checker(iplist, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    iplist = iplist.split('\n')  # Split IP list by newline
    iplistresult = []
    for ip in iplist[:1000]:  # Limit to 1000 IPs
        querystring = {
            'ipAddress': ip.strip(),
            'maxAgeInDays': '90'
        }
        response = requests.request(method='GET', url=url, headers=headers, params=querystring)
        if response.status_code == 200:
            iplistresult.append(response.json().get('data', {}))
    return iplistresult

# Streamlit UI
st.title("IP Reputation Check")

# Tab for API key input
st.sidebar.header("Configuration")
api_key = st.sidebar.text_input("Enter your AbuseIPDB API Key", type="password")
if not api_key:
    st.sidebar.warning("Please enter your API key to proceed.")

# Bulk IOC Checker
st.header("Bulk IOC Checker")
bulkiocvalues = st.text_area("Enter Bulk IPs (one per line):")
iocvaluesubmit = st.button("Submit")

if iocvaluesubmit and api_key:
    try:
        # Get bulk results
        bulkresult = bulk_abuseipddb_ioc_checker(bulkiocvalues, api_key)
        if bulkresult:
            df = pd.DataFrame.from_dict(bulkresult)
            st.dataframe(df)
        else:
            st.warning("No data returned. Check the IPs or API key.")
    except Exception as e:
        st.error(f"An error occurred: {e}")
elif iocvaluesubmit:
    st.error("Please provide your API key to perform the lookup.")

# Footer with credit
st.markdown("---")
st.markdown("### Powered by Ganesh Raja")

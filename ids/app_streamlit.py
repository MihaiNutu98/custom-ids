import streamlit as st
import pandas as pd

st.title("Custom IDS Demo")

# test data
df = pd.DataFrame({
    "Source IP": ["127.0.0.1", "192.168.0.1"],
    "Category": ["port_scan", "ssh_bruteforce"],
    "Severity": [5, 8]
})

st.table(df)

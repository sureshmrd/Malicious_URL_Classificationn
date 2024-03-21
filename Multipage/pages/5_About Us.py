# -*- coding: utf-8 -*-
"""
Created on Sun Mar 17 11:19:33 2024

@author: Suresh
"""
import streamlit as st
st.title("About Us")



st.write("We are From **SIR CR REDDY COLLEGE OF ENGINEERING** , Eluru")
st.write("From **Computer Science and Engineering** Branch , Section : B")
st.write("**BATCH - 5**")
data = [
        {"Name": "K.Anvesh Reddy", "RegisterNumber": "20B81A0587"},
        {"Name": "K.Mahendra Reddy", "RegisterNumber": "20B81A0588"},
        {"Name": "K.Ramya Chandrika", "RegisterNumber": "20B81A0589"},
        {"Name": "M.Vamsi Babu", "RegisterNumber": "20B81A0590"},
        {"Name": "M.R.D Suresh", "RegisterNumber": "20B81A0591"}
    ]

html_table = "<table><tr><th>Name</th><th>RegisterNumber</th></tr>"
for item in data:
    html_table += f"<tr><td>{item['Name']}</td><td>{item['RegisterNumber']}</td></tr>"
html_table += "</table>"

    # Display the HTML table
st.write(html_table, unsafe_allow_html=True)

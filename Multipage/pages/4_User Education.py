# -*- coding: utf-8 -*-
"""
Created on Thu Mar 21 08:57:05 2024

@author: Suresh
"""

import streamlit as st

def main():
    st.title("User Education Guide: Protecting Yourself From Cyber Attacks Related To URLs.")
    st.write("---")

    st.header("Understanding Malicious URLs")
    st.write("Malicious URLs are web addresses that have been created with the intent to deceive or harm users. They often mimic legitimate websites or contain malicious content designed to exploit vulnerabilities in your system.")

    st.write("---")

    st.header("Types of Cyber Threats Associated with Malicious URLs")

    st.subheader("1. Phishing Attacks")
    st.write("- **Description**: Phishing attacks involve tricking users into divulging sensitive information, such as usernames, passwords, or financial details, by masquerading as trustworthy entities.")
    st.write("- **Precautions**: Always verify the authenticity of emails and website URLs before providing any personal information. Look out for misspellings, suspicious links, and requests for sensitive data.")

    st.write("---")

    st.subheader("2. Malware Infections")
    st.write("- **Description**: Malicious URLs may host malware, such as viruses, ransomware, or spyware, which can infect your device and compromise your data.")
    st.write("- **Precautions**: Install reputable antivirus software and keep it up to date. Avoid downloading files from unfamiliar or suspicious websites, and be cautious when clicking on links in emails or messages.")

    st.write("---")

    st.subheader("3. Data Breaches")
    st.write("- **Description**: Malicious URLs can lead to data breaches by exploiting vulnerabilities in websites or applications, allowing cybercriminals to steal sensitive information, such as personal data, financial records, or login credentials.")
    st.write("- **Precautions**: Use strong, unique passwords for each online account and enable two-factor authentication whenever possible. Regularly monitor your accounts for any suspicious activity and report any unauthorized access immediately.")

    st.write("---")

    st.header("Safe Browsing Practices")

    st.write("1. **Verify Website URLs**: Before clicking on a link, hover your mouse cursor over it to preview the URL. Ensure that it matches the expected domain and doesn't contain any unusual characters or misspellings.")
    st.write("2. **Use HTTPS**: Look for the padlock icon and 'https://' in the URL bar, indicating a secure connection. Avoid entering sensitive information on websites that only use HTTP.")
    st.write("3. **Update Software**: Keep your operating system, web browser, and security software updated with the latest patches and security fixes to protect against known vulnerabilities.")
    st.write("4. **Exercise Caution**: Be skeptical of unsolicited emails, messages, or pop-up ads asking for personal or financial information. If something seems too good to be true, it probably is.")

    st.write("---")

    st.header("Conclusion")
    st.write("By understanding the risks associated with malicious URLs and adopting safe browsing practices, you can significantly reduce your exposure to cyber threats and protect your sensitive information online. Remember to stay vigilant, stay informed, and stay safe!")

if __name__ == "__main__":
    main()

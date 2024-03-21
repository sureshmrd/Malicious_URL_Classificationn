import streamlit as st
import numpy as np
import re
from urllib.parse import urlparse
from tld import get_tld
import pickle



st.title("Detail about Classification Report")

inp=st.session_state.my_input
st.write("You Entered the URL : ",inp)
loaded_model1=pickle.load(open("project_model_final_2.sav","rb"))

def pred(input):
    test=get_prediction_from_url(input)
    tt=loaded_model1.predict(test)
    if int(tt[0]) == 0:
        res="SAFE"
        return res
    elif int(tt[0]) == 1.0:
        
        res="DEFACEMENT"
        return res
    elif int(tt[0]) == 2.0:
        res="PHISHING"
        return res
        
    elif int(tt[0]) == 3.0:
        
        res="MALWARE"
        return res
    
def get_prediction_from_url(test_url):
    features_test = main1(test_url)
    # Due to updates to scikit-learn, we now need a 2D array as a parameter to the predict function.
    features_test = np.array(features_test).reshape((1, -1))
    return features_test

def main1(url):
    
    status = []
    
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(count_atrate(url))
    status.append(no_of_dir(url))
    status.append(no_of_embed(url))
    
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    
    status.append(count_per(url))
    status.append(count_ques(url))
    status.append(count_hyphen(url))
    status.append(count_equal(url))
    
    status.append(url_length(url))
    status.append(hostname_length(url))
    status.append(suspicious_words(url))
    status.append(digit_count(url))
    status.append(letter_count(url))
    status.append(fd_length(url))
    tld = get_tld(url,fail_silently=True)
      
    status.append(tld_length(tld))
    
    
    

    return status


#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0



def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
       
        # print 'No matching pattern found'
        return 0
    


def count_dot(url):
    count_dot = url.count('.')
   
    return count_dot


def count_www(url):
    d=url.count('www')
    return d



def count_atrate(url):
    e=url.count('@')
    return e




def no_of_dir(url):
    urldir = urlparse(url).path
    f=urldir.count('/')
    return f



def no_of_embed(url):
    urldir = urlparse(url).path
    
    return urldir.count('//')




def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
       
        return 1
    else:
        
        return 0
    
    


def count_https(url):
    
    return url.count('https')


def count_http(url):
    
    return url.count('http')


def count_per(url):
    
    return url.count('%')


def count_ques(url):
   
    return url.count('?')


def count_hyphen(url):
    
    return url.count('-')


def count_equal(url):
   
    return url.count('=')


def url_length(url):
    
    return len(str(url))




def hostname_length(url):
    
    return len(urlparse(url).netloc)




def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
                      url)
    if match:
        
        return 1
    else:
        
        return 0



def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    
    return digits




def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
  
    return letters






def fd_length(url):
    urlpath= urlparse(url).path
    try:
        
        return len(urlpath.split('/')[1])
    except:
     
        return 0



def tld_length(tld):
    try:
        
        return len(tld)
    except:
        
        return -1







b=abnormal_url(inp)
if b==0:
    b=False
else:
    b=True
c=count_dot(inp)
d=count_www(inp)
e=count_atrate(inp)
f=no_of_dir(inp)
g=no_of_embed(inp)
h=shortening_service(inp)
i=count_https(inp)
j=count_http(inp)
k=count_per(inp)
l=count_ques(inp)
m=count_hyphen(inp)
n=count_equal(inp)
o=url_length(inp)
p=hostname_length(inp)
q=suspicious_words(inp)
r=digit_count(inp)
s=letter_count(inp)
t=fd_length(inp)
u=tld_length(get_tld(inp,fail_silently=True))


all_data1={"Abnormal URL":b,"Count dot - counts no .of dots":c,"Count WWW":d,"Count atrate(@)":e,"No of dir":f,"No of embed":g,"Shortening Service":h,"Count https":i,"Count http":j,"Count Per(%)":k}
all_data2={"Count ques(?)":l,"Count hyphen(-)":m,"Count equal(=)":n,"URL Length":o,"Hostname Length":p,"Suspious Words":q,"Digit Count":r,"Letter Count":s,"Fd Length":t,"Tld Length":u}
result2 = pred(inp)



def generate_html_table(data, table_name):
    html_table = f"<table style='border-collapse: collapse; border-spacing: 0; border: 1px solid black; padding: 10px;'>" \
                 f"<caption style='padding: 10px;'><strong>{table_name}</strong></caption>" \
                 f"<thead><tr style='background-color: #f2f2f2; color: black;'><th style='padding: 10px;'>Factor</th>" \
                 f"<th style='padding: 10px;'>Value</th></tr></thead>"
    # Adding table body
    for key, value in data.items():
        html_table += f"<tr style='border: 1px solid black;'><td style='padding: 10px;'>{key}</td>" \
                      f"<td style='padding: 10px;'>{value}</td></tr>"
    html_table += "</table>"
    return html_table

html_table1 = generate_html_table(all_data1, "")
html_table2 = generate_html_table(all_data2, "")
# Display the HTML table
st.write(" ")
st.header('CLASSIFICATION TABLE')
st.write(f'<div style="display:flex">{html_table1}<div style="margin-left:60px"></div>{html_table2}</div>', unsafe_allow_html=True)


st.header('Lexical Features:')
    
st.subheader('General Features:')
st.markdown("""
    - **Abnormal_URL**: Malicious URLs often contain obfuscated or random characters to evade detection, so URLs flagged as abnormal may be more likely to be classified as malicious..
    - **Google_Index**: Legitimate websites are more likely to be indexed by Google, so URLs not indexed may be considered suspicious.
    - **Count**: Malicious URLs may be longer or shorter than typical benign URLs, so the length of the URL could be indicative of its nature.
    """)
    
    
st.subheader('Domain/Subdomain Features:')
st.markdown("""
    - **count-www**: Presence of multiple 'www' subdomains might indicate an attempt to impersonate a legitimate website, common in phishing attacks..
    - **count@**: Often used in phishing attacks to disguise the true destination of the URL.
    - **count_dir**:Malicious URLs may have complex directory structures or none at all, differing from typical benign URLs.
    - **count_embed_domain**: Malicious actors might use subdomains to hide the true destination of the URL, commonly seen in phishing attacks.
    - **short_url**: Shortened URLs are often used to mask malicious destinations.
    - **fd_length**: Malicious actors may use long or complex FQDNs to evade detection..
    - **tld**: Top-Level Domain (TLD).
    - **tld_length**: Certain TLDs are more commonly associated with malicious activity, and unusual TLD lengths could indicate suspicious URLs.
    """)



st.subheader('Protocol Features:')
st.markdown("""
    - **count-https**: Count occurrences of 'https' in the URL.
    - **count-http**: Count occurrences of 'http' in the URL.
    - The presence or absence of secure HTTPS protocol can be indicative of the URL's trustworthiness.
    """)
    
st.subheader('Special Character Features:')
st.markdown("""
    - **count%**, **count?**, **count-**, **count=**: Count occurrences of special characters.
    - Unusual or excessive usage of these characters may signal malicious intent.
    """)


st.subheader('Length Features:')
st.markdown("""
    - **url_length**: Length of the entire URL.
    - **hostname_length**: Length of the hostname part of the URL.
    - Length of the entire URL and the hostname part of the URL, respectively.
      Similar to the total count, length can indicate potential maliciousness if it deviates significantly from typical benign URLs.
    - **count-digits & letters**: Count occurrences of digits in the URL.
    -  Unusual patterns in digit or letter counts may indicate maliciousness.
    """)






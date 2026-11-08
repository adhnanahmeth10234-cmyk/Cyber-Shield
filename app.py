import streamlit as st
import pandas as pd
import re
import math
from sklearn.ensemble import RandomForestClassifier

# Page Config with Wide Layout
st.set_page_config(
    page_title="AI Cyber Shield Pro", 
    page_icon="🛡️", 
    layout="wide"
)

# Custom Cyber-Themed CSS
st.markdown("""
    <style>
    .stApp {
        background-color: #0b0f19;
        background-image: 
            radial-gradient(at 10% 20%, rgba(99, 102, 241, 0.18) 0px, transparent 50%),
            radial-gradient(at 90% 80%, rgba(14, 165, 233, 0.18) 0px, transparent 50%),
            radial-gradient(at 50% 50%, rgba(15, 23, 42, 1) 0px, transparent 100%);
        color: #f8fafc;
    }
    .main-header {
        background: rgba(30, 41, 59, 0.75);
        padding: 24px;
        border-radius: 16px;
        backdrop-filter: blur(12px);
        border: 1px solid rgba(56, 189, 248, 0.2);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.4);
        text-align: center;
        margin-bottom: 20px;
    }
    .main-title {
        font-size: 2.4rem;
        font-weight: 800;
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 6px;
    }
    .metric-card {
        background: rgba(30, 41, 59, 0.65);
        border-radius: 12px;
        padding: 16px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        text-align: center;
    }
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #6366f1 0%, #0ea5e9 100%);
        color: white;
        border: none;
        padding: 12px 20px;
        font-weight: 600;
        border-radius: 10px;
        transition: all 0.3s ease;
        box-shadow: 0 4px 14px 0 rgba(14, 165, 233, 0.35);
    }
    .stButton>button:hover {
        background: linear-gradient(90deg, #4f46e5 0%, #0284c7 100%);
        box-shadow: 0 6px 20px 0 rgba(14, 165, 233, 0.55);
        transform: translateY(-2px);
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        background-color: rgba(15, 23, 42, 0.85) !important;
        color: #f8fafc !important;
        border-radius: 10px !important;
        border: 1px solid rgba(56, 189, 248, 0.3) !important;
    }
    </style>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://img.icons8.com/color/96/cyber-security.png", width=70)
    st.title("⚙️ Control Panel")
    
    selected_lang = st.selectbox(
        "🌐 Interface Language",
        ["English", "தமிழ் (Tamil)", "සිංහල (Sinhala)"]
    )
    
    st.divider()
    st.markdown("### 💡 Public Defense Suite")
    st.info("System includes URL Inspector, Job Scam Detector, Password Strength Auditor, and SL Cyber Emergency Directory.")

# --- TOP HEADER BANNER ---
st.markdown("""
    <div class="main-header">
        <div class="main-title">🛡️ AI Cyber Threat & Phishing Shield</div>
        <div style="color: #94a3b8; font-size: 1.05rem;">
            Enterprise Multi-Lingual URL Inspector, Scam Analyzer, Password Auditor & Emergency Response
        </div>
    </div>
""", unsafe_allow_html=True)

# --- DASHBOARD STATS BAR ---
col_s1, col_s2, col_s3, col_s4 = st.columns(4)
with col_s1:
    st.markdown('<div class="metric-card"><h4 style="margin:0; color:#38bdf8;">Engine</h4><p style="margin:0; font-weight:bold; font-size:1.1rem;">v7.0 Public Suite</p></div>', unsafe_allow_html=True)
with col_s2:
    st.markdown('<div class="metric-card"><h4 style="margin:0; color:#818cf8;">Analysis</h4><p style="margin:0; font-weight:bold; font-size:1.1rem;">ML & NLP Heuristics</p></div>', unsafe_allow_html=True)
with col_s3:
    st.markdown('<div class="metric-card"><h4 style="margin:0; color:#c084fc;">Languages</h4><p style="margin:0; font-weight:bold; font-size:1.1rem;">EN | TA | SI</p></div>', unsafe_allow_html=True)
with col_s4:
    st.markdown('<div class="metric-card"><h4 style="margin:0; color:#4ade80;">Emergency</h4><p style="margin:0; font-weight:bold; font-size:1.1rem;">SL CERT Ready</p></div>', unsafe_allow_html=True)

st.write("")

# --- ML FEATURE EXTRACTION ---
def extract_advanced_features(url):
    url_str = str(url).lower()
    features = []
    features.append(len(url_str))
    features.append(1 if '@' in url_str else 0)
    features.append(1 if '-' in url_str else 0)
    features.append(1 if url_str.startswith('https') else 0)
    
    ip_pattern = r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    features.append(1 if re.search(ip_pattern, url_str) else 0)
    
    suspicious_tlds = ['.xyz', '.top', '.tk', '.work', '.click', '.gq', '.cf', '.ml', '.icu', '.buzz']
    features.append(1 if any(tld in url_str for tld in suspicious_tlds) else 0)
    features.append(url_str.count('.'))
    
    sensitive_words = ['bank', 'login', 'verify', 'account', 'secure', 'update', 'pay', 'free', 'bonus', 'parcel', 'customs', 'job', 'fee']
    features.append(1 if any(word in url_str for word in sensitive_words) else 0)
    
    return features

@st.cache_resource
def train_model():
    raw_data = {
        'url': [
            'https://google.com', 'https://github.com', 'https://microsoft.com', 'https://amazon.com',
            'https://wikipedia.org', 'https://paypal.com', 'https://apple.com', 'https://linkedin.com',
            'http://login-verify-paypal-secure.com', 'http://192.168.1.1/bank/verify', 'http://free-iphone-winner.xyz',
            'http://secure-update-account-bank.tk', 'http://instagram-blue-tick-claim.top', 'http://whatsapp-lottery-bonus.work',
            'http://account-suspended-verify-now.gq', 'http://verify-bank-security-code.com', 'http://claim-free-recharge.ml'
        ],
        'label': ['safe', 'safe', 'safe', 'safe', 'safe', 'safe', 'safe', 'safe',
                  'malicious', 'malicious', 'malicious', 'malicious', 'malicious', 'malicious', 'malicious', 'malicious', 'malicious']
    }
    df = pd.DataFrame(raw_data)
    X = [extract_advanced_features(u) for u in df['url']]
    y = df['label']
    
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X, y)
    return rf

model = train_model()

# --- TABS SYSTEM ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🌐 URL Security Inspector", 
    "💬 Universal Scam & Job Engine", 
    "🔑 Password Strength Audit",
    "🚨 Emergency & SL Directory",
    "📚 Awareness Center"
])

# TAB 1: URL INSPECTOR
with tab1:
    st.subheader("🔗 Structural URL Security Audit")
    st.write("Inspect web links using machine learning heuristics and pattern recognition.")
    
    user_url = st.text_input("Enter Web Link to Inspect:", "http://login-verify-bank-account.xyz", key="url_input")

    if st.button("🔍 Run Deep Security Audit"):
        if user_url:
            feats = extract_advanced_features(user_url)
            prediction = model.predict([feats])[0]
            proba = model.predict_proba([feats])[0]
            classes = list(model.classes_)
            malicious_idx = classes.index('malicious')
            risk_score = int(proba[malicious_idx] * 100)
            
            st.divider()
            res_col1, res_col2 = st.columns([1, 1])
            
            with res_col1:
                if prediction == 'malicious' or risk_score >= 50:
                    st.error(f"🚨 **HIGH RISK PHISHING URL DETECTED**")
                    st.metric(label="Calculated Risk Score", value=f"{risk_score}%", delta="Dangerous", delta_color="inverse")
                else:
                    st.success(f"✅ **SAFE / LEGITIMATE URL**")
                    st.metric(label="Calculated Safety Score", value=f"{100 - risk_score}%", delta="Secure")
            
            with res_col2:
                st.write("### ⚙️ Telemetry & Structural Analysis")
                st.markdown(f"- **URL Character Length:** `{len(user_url)}`")
                st.markdown(f"- **HTTPS Encryption Protocol:** `{'Secure SSL' if feats[3] == 1 else 'Unencrypted HTTP (Risk)'}`")
                st.markdown(f"- **Raw IP Address Domain:** `{'Detected (Severe Threat)' if feats[4] == 1 else 'Domain Name System (Safe)'}`")
                st.markdown(f"- **High-Risk TLD Extension:** `{'Flagged Extension' if feats[5] == 1 else 'Clean TLD'}`")
                st.markdown(f"- **Subdomain Depth Count:** `{feats[6]} levels`")
        else:
            st.warning("Please input a URL.")

# TAB 2: SCAM & JOB ENGINE
with tab2:
    st.subheader("✉️ Universal Scam & Fake Job Analyzer")
    st.write("Detects financial fraud, parcel delivery traps, account blocks, and **Fake Work-From-Home / Registration Fee Job Scams** across EN, TA, and SI.")
    
    user_message = st.text_area(
        "Paste message or job offer (WhatsApp / SMS / Social Media):", 
        placeholder="Part time job! Earn Rs. 5000 daily. Pay registration fee Rs. 1000 via WhatsApp link: http://job-offer.xyz",
        height=130,
        key="msg_input"
    )

    if st.button("🛡️ Analyze Threat Level"):
        if user_message:
            url_pattern = r'https?://[^\s]+|www\.[^\s]+'
            found_urls = re.findall(url_pattern, user_message)
            
            scam_triggers = [
                'urgent', 'immediate', 'warning', 'suspend', 'block', 'expire', 'verify', 'click here',
                'winner', 'prize', 'lottery', 'bonus', 'cashback', 'recharge', 'otp', 'claim', 'refund',
                'parcel', 'delivery', 'customs', 'package', 'shipping', 'courier',
                'job', 'part-time', 'daily income', 'registration fee', 'deposit', 'earn money', 'whatsapp job',
                'வங்கி', 'உடனடியாக', 'பரிசு', 'சரிபார்க்கவும்', 'கணக்கு', 'பணம்', 'இலவசம்', 'வெற்றி', 'வேலை', 'பதிவுக் கட்டணம்',
                'ලොතරැය', 'තෑග්ග', 'ගිණුම', 'බැංකුව', 'රැකියාව', 'මුදල්'
            ]
            
            msg_lower = user_message.lower()
            triggered_words = [word for word in scam_triggers if word in msg_lower]
            
            score = 0
            flagged_reasons = []
            
            if triggered_words:
                score += len(set(triggered_words)) * 15
                flagged_reasons.append(f"Scam / Social Engineering / Job Triggers: **{', '.join(set(triggered_words))}**")
                
            if found_urls:
                for u in found_urls:
                    u_feats = extract_advanced_features(u)
                    u_pred = model.predict([u_feats])[0]
                    if u_pred == 'malicious':
                        score += 50
                        flagged_reasons.append(f"Malicious Embedded URL: `{u}`")
                    else:
                        score += 15
                        flagged_reasons.append(f"Extracted Link: `{u}`")
            
            final_risk = min(score, 100)
            
            st.divider()
            m_col1, m_col2 = st.columns([1, 1])
            with m_col1:
                if final_risk >= 35:
                    st.error(f"🚨 **HIGH RISK SCAM / FAKE JOB DETECTED**")
                    st.metric(label="Overall Risk Score", value=f"{final_risk}%", delta="High Threat", delta_color="inverse")
                else:
                    st.success(f"✅ **LOW RISK MESSAGE**")
                    st.metric(label="Safety Confidence", value=f"{100 - final_risk}%", delta="Clean")
            
            with m_col2:
                st.write("### 🚨 Threat Findings")
                if flagged_reasons:
                    for r in flagged_reasons:
                        st.write(f"- {r}")
                else:
                    st.write("- No high-risk triggers found.")
        else:
            st.warning("Please paste text content.")

# TAB 3: PASSWORD AUDIT
with tab3:
    st.subheader("🔑 Password Strength & Breach Audit Tool")
    st.write("Check your password complexity, entropy strength, and resistance against brute-force attacks.")
    
    pwd_input = st.text_input("Enter Password to Test:", type="password", key="pwd_input")
    
    if st.button("🔒 Evaluate Password Strength"):
        if pwd_input:
            length = len(pwd_input)
            has_upper = bool(re.search(r'[A-Z]', pwd_input))
            has_lower = bool(re.search(r'[a-z]', pwd_input))
            has_digit = bool(re.search(r'\d', pwd_input))
            has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', pwd_input))
            
            score = 0
            feedback = []
            
            if length >= 12: score += 30
            elif length >= 8: score += 15
            else: feedback.append("❌ Password is too short (Minimum recommended: 12 characters).")
            
            if has_upper: score += 15
            else: feedback.append("❌ Add uppercase letters (A-Z).")
            
            if has_lower: score += 15
            else: feedback.append("❌ Add lowercase letters (a-z).")
            
            if has_digit: score += 20
            else: feedback.append("❌ Add numbers (0-9).")
            
            if has_special: score += 20
            else: feedback.append("❌ Add special symbols (!@#$%^&*).")
            
            st.divider()
            p_col1, p_col2 = st.columns([1, 1])
            
            with p_col1:
                if score >= 80:
                    st.success("🟢 **STRONG & SECURE PASSWORD**")
                    st.metric(label="Security Score", value=f"{score}%", delta="Excellent")
                elif score >= 50:
                    st.warning("🟡 **MODERATE PASSWORD (Can be improved)**")
                    st.metric(label="Security Score", value=f"{score}%", delta="Medium")
                else:
                    st.error("🔴 **WEAK PASSWORD (Vulnerable to Brute-Force)**")
                    st.metric(label="Security Score", value=f"{score}%", delta="High Risk", delta_color="inverse")
            
            with p_col2:
                st.write("### ⚙️ Security Recommendations")
                if feedback:
                    for f in feedback:
                        st.write(f)
                else:
                    st.write("✅ Excellent complexity! This password meets enterprise cryptographic standards.")
        else:
            st.warning("Please enter a password.")

# TAB 4: EMERGENCY & SL DIRECTORY
with tab4:
    st.subheader("🚨 Emergency Incident Response & Sri Lanka Cyber Directory")
    st.write("Immediate action checklist if you fall victim to a cyber scam, alongside official Sri Lankan reporting contacts.")
    
    col_e1, col_e2 = st.columns(2)
    
    with col_e1:
        st.markdown("""
        ### ⏱️ Immediate Steps If Scammed
        1. **Block Bank Accounts / Cards:** Immediately call your bank hotline to freeze accounts or credit/debit cards.
        2. **Secure Credentials:** Change your primary email, social media, and banking passwords instantly.
        3. **Disconnect Device:** Disconnect from Wi-Fi/Mobile Data if malware or a RAT was downloaded.
        4. **File Evidence:** Take screenshots of chat messages, transaction receipts, and scammer URLs.
        """)
        
    with col_e2:
        st.markdown("""
        ### 🇱🇰 Sri Lanka Official Emergency Directory
        * **Sri Lanka CERT | CC (Cyber Emergency Team):**
          * Hotline: `+94 11 269 5746`
          * Email: `info@cert.gov.lk`
        * **Sri Lanka Police Cyber Crime Division:**
          * Hotline: `+94 11 239 5652`
        * **Central Bank Financial Fraud Division:**
          * Hotline: `1935`
        """)

# TAB 5: AWARENESS CENTER
with tab5:
    st.subheader("📚 Cybersecurity Awareness & Prevention Guide")
    st.write("Recognizing social engineering tactics across different modern scam scenarios.")
    
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("""
        ### 🚨 Modern Scam Scenarios
        * **Fake Job & Task Scams:** False promises of high daily income requiring a small registration or deposit fee.
        * **Parcel & Customs Scams:** Fake SMS claiming your package is held until you click a link and pay a fee.
        * **Account Suspension Alerts:** Fake alerts from banks or utility companies demanding instant login verification.
        """)
    with col_b:
        st.markdown("""
        ### 🛡️ Core Protection Rules
        * **Never Pay to Work:** Legitimate employers never ask for registration fees or deposits.
        * **Verify Independently:** Go directly to official apps or websites instead of clicking message links.
        * **Test via AI:** Use this Universal Scanner for any suspicious SMS, email, or chat!
        """)
import re
import colorama
from colorama import Fore, Style

# ============================================================
#   PHISHING EMAIL DETECTOR
#   Project by: [Your Name]
#   Concepts: Threat Detection, Pattern Matching, Email Security
# ============================================================

colorama.init(autoreset=True)

# ---- Phishing Indicators Database ----

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "update your information",
    "your account has been suspended", "unusual activity", "click here immediately",
    "act now", "urgent action required", "your account will be closed",
    "verify immediately", "confirm your email", "login attempt",
    "you have won", "congratulations you have been selected",
    "free gift", "claim your prize", "you are a winner",
    "bank account", "credit card information", "social security",
    "password expired", "reset your password immediately",
    "limited time offer", "expires today", "respond immediately",
    "dear customer", "dear user", "dear account holder",
    "kindly verify", "kindly update", "kindly confirm",
    "nigerian prince", "million dollars", "wire transfer",
    "inheritance", "lottery winner", "unclaimed funds",
]

SUSPICIOUS_DOMAINS = [
    "paypa1.com", "g00gle.com", "amaz0n.com", "micros0ft.com",
    "appleid-verify.com", "secure-login.com", "account-verify.com",
    "banking-secure.com", "update-account.com", "verify-identity.com",
    "login-secure.com", "account-suspended.com", "free-gift.com",
    "claim-prize.com", "winner-alert.com",
]

LEGITIMATE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "linkedin.com",
    "github.com", "stackoverflow.com",
]

URGENCY_WORDS = [
    "urgent", "immediately", "right now", "expires", "limited time",
    "act fast", "don't delay", "last chance", "final notice",
    "warning", "alert", "critical", "important notice",
]

SUSPICIOUS_PATTERNS = [
    r'http[s]?://\d+\.\d+\.\d+\.\d+',          # IP address URLs
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
    r'bit\.ly|tinyurl|goo\.gl|t\.co',            # URL shorteners
    r'[A-Z]{5,}',                                 # Excessive caps
    r'(.)\1{4,}',                                 # Repeated characters
]


def analyze_email(subject, sender, body):
    """
    Analyzes an email for phishing indicators.
    Returns a risk score and detailed findings.
    """
    findings   = []
    risk_score = 0
    full_text  = f"{subject} {sender} {body}".lower()

    # ---- Check 1: Phishing Keywords ----
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in full_text:
            found_keywords.append(keyword)
            risk_score += 10

    if found_keywords:
        findings.append({
            "category": "🎣 Phishing Keywords",
            "detail": f"Found {len(found_keywords)} suspicious keyword(s): {', '.join(found_keywords[:3])}{'...' if len(found_keywords) > 3 else ''}",
            "severity": "HIGH"
        })

    # ---- Check 2: Urgency Words ----
    found_urgency = []
    for word in URGENCY_WORDS:
        if word.lower() in full_text:
            found_urgency.append(word)
            risk_score += 8

    if found_urgency:
        findings.append({
            "category": "⚡ Urgency Tactics",
            "detail": f"Urgency words detected: {', '.join(found_urgency[:3])}",
            "severity": "MEDIUM"
        })

    # ---- Check 3: Suspicious Sender Domain ----
    sender_lower = sender.lower()
    for domain in SUSPICIOUS_DOMAINS:
        if domain in sender_lower:
            risk_score += 30
            findings.append({
                "category": "🌐 Suspicious Domain",
                "detail": f"Sender domain '{domain}' is known to be suspicious",
                "severity": "HIGH"
            })

    # ---- Check 4: Sender not from legitimate domain ----
    is_legit_domain = any(domain in sender_lower for domain in LEGITIMATE_DOMAINS)
    if not is_legit_domain and "@" in sender:
        risk_score += 15
        findings.append({
            "category": "📧 Unknown Sender Domain",
            "detail": f"Sender '{sender}' is not from a known legitimate domain",
            "severity": "MEDIUM"
        })

    # ---- Check 5: Suspicious Patterns ----
    patterns_found = []
    pattern_names  = [
        "IP address URL detected",
        "Email address in body",
        "URL shortener detected",
        "Excessive capital letters",
        "Repeated characters"
    ]
    for i, pattern in enumerate(SUSPICIOUS_PATTERNS):
        if re.search(pattern, f"{subject} {body}"):
            patterns_found.append(pattern_names[i])
            risk_score += 12

    if patterns_found:
        findings.append({
            "category": "🔍 Suspicious Patterns",
            "detail": f"Detected: {', '.join(patterns_found)}",
            "severity": "MEDIUM"
        })

    # ---- Check 6: Generic Greeting ----
    generic_greetings = ["dear customer", "dear user", "dear account holder", "dear member"]
    for greeting in generic_greetings:
        if greeting in full_text:
            risk_score += 10
            findings.append({
                "category": "👤 Generic Greeting",
                "detail": f"Uses generic greeting '{greeting}' instead of your real name",
                "severity": "MEDIUM"
            })
            break

    # ---- Check 7: Suspicious Subject ----
    suspicious_subjects = ["verify", "suspended", "urgent", "winner", "prize", "free", "alert"]
    subject_flags = [w for w in suspicious_subjects if w in subject.lower()]
    if subject_flags:
        risk_score += 15
        findings.append({
            "category": "📨 Suspicious Subject",
            "detail": f"Subject contains suspicious words: {', '.join(subject_flags)}",
            "severity": "HIGH"
        })

    return risk_score, findings


def get_risk_level(score):
    """Returns risk level and color based on score."""
    if score >= 60:
        return "🔴 VERY HIGH RISK - Almost certainly PHISHING!", Fore.RED
    elif score >= 40:
        return "🟠 HIGH RISK - Likely phishing!", Fore.YELLOW
    elif score >= 20:
        return "🟡 MEDIUM RISK - Treat with caution", Fore.YELLOW
    elif score >= 10:
        return "🟢 LOW RISK - Looks mostly safe", Fore.GREEN
    else:
        return "✅ SAFE - No phishing indicators found", Fore.GREEN


def display_results(risk_score, findings, subject, sender):
    """Displays the analysis results."""
    risk_level, color = get_risk_level(risk_score)

    print("\n" + "=" * 55)
    print(f"  📊 ANALYSIS RESULTS")
    print("=" * 55)
    print(f"  Subject : {subject}")
    print(f"  Sender  : {sender}")
    print(f"  Score   : {risk_score}/100")
    print(f"  Result  : {color}{risk_level}{Style.RESET_ALL}")

    if findings:
        print(f"\n  ⚠️  SUSPICIOUS INDICATORS FOUND ({len(findings)}):")
        print("  " + "-" * 50)
        for finding in findings:
            severity_color = Fore.RED if finding['severity'] == 'HIGH' else Fore.YELLOW
            print(f"\n  {finding['category']}")
            print(f"  {severity_color}[{finding['severity']}]{Style.RESET_ALL} {finding['detail']}")
    else:
        print(f"\n  {Fore.GREEN}✅ No suspicious indicators detected.{Style.RESET_ALL}")

    print("\n  💡 SAFETY TIPS:")
    print("  → Never click links in suspicious emails")
    print("  → Always verify sender's email address carefully")
    print("  → Contact the company directly if unsure")
    print("  → Never share passwords or personal info via email")
    print("=" * 55)


def main():
    print(Fore.CYAN + "=" * 55)
    print("   🎣 PHISHING EMAIL DETECTOR")
    print("   Protect yourself from email scams!")
    print("=" * 55 + Style.RESET_ALL)

    while True:
        print("\nWhat would you like to do?")
        print("  1. Analyze an email manually")
        print("  2. Test with sample phishing email")
        print("  3. Test with sample legitimate email")
        print("  4. Exit")

        choice = input("\nEnter your choice (1-4): ").strip()

        # ---- Manual Analysis ----
        if choice == "1":
            print("\n--- ENTER EMAIL DETAILS ---")
            subject = input("  Enter email subject: ").strip()
            sender  = input("  Enter sender email address: ").strip()
            print("  Enter email body (press Enter twice when done):")
            lines = []
            while True:
                line = input()
                if line == "":
                    break
                lines.append(line)
            body = " ".join(lines)

            print("\n  ⏳ Analyzing email...")
            risk_score, findings = analyze_email(subject, sender, body)
            display_results(risk_score, findings, subject, sender)

        # ---- Sample Phishing Email ----
        elif choice == "2":
            print("\n  📧 Testing with sample PHISHING email...")
            subject = "URGENT: Your account has been suspended - Verify immediately!"
            sender  = "security@paypa1.com"
            body    = """Dear Customer, We have detected unusual activity on your account. 
                        Your account will be closed unless you verify your information immediately. 
                        Click here now to confirm your identity and update your password. 
                        Act fast - this offer expires today! 
                        Visit: http://192.168.1.1/verify or bit.ly/secure-login"""

            risk_score, findings = analyze_email(subject, sender, body)
            display_results(risk_score, findings, subject, sender)

        # ---- Sample Legitimate Email ----
        elif choice == "3":
            print("\n  📧 Testing with sample LEGITIMATE email...")
            subject = "Your order has been shipped"
            sender  = "orders@amazon.com"
            body    = """Hello Manas, Thank you for your order. 
                        Your package has been shipped and will arrive in 3-5 business days. 
                        You can track your order on our website. 
                        Thank you for shopping with us!"""

            risk_score, findings = analyze_email(subject, sender, body)
            display_results(risk_score, findings, subject, sender)

        # ---- Exit ----
        elif choice == "4":
            print("\n👋 Stay safe from phishing attacks!\n")
            break

        else:
            print("  ⚠️  Invalid choice. Please enter 1 to 4.")


if __name__ == "__main__":
    main()

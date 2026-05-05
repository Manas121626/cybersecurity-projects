# 🔐 Cybersecurity Projects Portfolio

> A collection of hands-on cybersecurity tools built in Python, demonstrating core concepts in network security, cryptography, and threat detection.

---

## 👨‍💻 About Me
I am a Computer Science student passionate about cybersecurity, currently building my skills toward pursuing an MS in Cybersecurity. These projects reflect my understanding of real-world security concepts and tools.

---

## 📁 Projects

### 1. 🔑 Password Strength Checker + Generator
**File:** `Password checker.py`

A tool that evaluates password strength based on security rules and generates cryptographically random passwords.

**Concepts Covered:**
- Password policies and security rules
- Character entropy and randomization
- Common password vulnerability detection

**Features:**
- Checks length, uppercase, lowercase, digits, special characters
- Detects commonly used weak passwords
- Generates strong random passwords with custom options
- Visual strength bar display

---

### 2. 🔍 Port Scanner
**File:** `port scanner.py`

A network reconnaissance tool that identifies open ports and potential security vulnerabilities on a target system.

**Concepts Covered:**
- TCP/IP networking fundamentals
- Socket programming
- Network security auditing
- Port states and services

**Features:**
- Scan common well-known ports
- Scan custom port ranges
- Single port scanning
- Service identification for each port
- Scan summary with security recommendations

---

### 3. 🔒 File Encryption / Decryption Tool
**File:** `file_encryption_tool.py`

A tool that encrypts and decrypts files and messages using industry-standard AES-256 encryption.

**Concepts Covered:**
- AES-256 Encryption
- PBKDF2 Key Derivation Function
- SHA-256 Hashing
- File integrity verification
- Salt-based randomization

**Features:**
- Encrypt and decrypt any file type
- Encrypt and decrypt text messages
- Generate SHA-256 hash for file integrity verification
- Password-based encryption with secure key derivation

---

### 4. 🎣 Phishing Email Detector
**File:** `phishing_detector.py`

A threat detection tool that analyzes emails for phishing indicators and assigns a risk score based on multiple security checks.

**Concepts Covered:**
- Threat detection and analysis
- Pattern matching and regex
- Email security
- Social engineering awareness

**Features:**
- Detects phishing keywords and urgency tactics
- Identifies suspicious sender domains
- Detects IP address URLs and URL shorteners
- Flags generic greetings and suspicious subjects
- Gives a risk score out of 100 with color coded results
- Includes sample phishing and legitimate email tests

---

## 🛠️ Technologies Used
- Python 3
- Socket Library (Networking)
- Cryptography Library (AES Encryption)
- Hashlib (SHA-256 Hashing)
- Colorama (Colored Terminal Output)
- Regex / Re Module (Pattern Matching)
- OS & Random modules

---

## 🚀 How to Run

**Clone the repository:**
```bash
git clone https://github.com/Manas121626/cybersecurity-projects.git
cd cybersecurity-projects
```

**Install required libraries:**
```bash
pip install cryptography colorama
```

**Run any project:**
```bash
python "Password checker.py"
python "port scanner.py"
python file_encryption_tool.py
python phishing_detector.py
```

---

## 📚 Concepts Demonstrated
| Concept | Project |
|---|---|
| Password Security | Password Checker |
| TCP/IP Networking | Port Scanner |
| AES-256 Encryption | File Encryption Tool |
| SHA-256 Hashing | File Encryption Tool |
| Network Reconnaissance | Port Scanner |
| Key Derivation (PBKDF2) | File Encryption Tool |
| Threat Detection | Phishing Detector |
| Pattern Matching | Phishing Detector |
| Email Security | Phishing Detector |
| Social Engineering Awareness | Phishing Detector |

---

## 📌 Note
These tools are built for **educational purposes only**.
Always ensure you have proper authorization before scanning any network or system.

---

⭐ Feel free to explore, learn, and contribute!

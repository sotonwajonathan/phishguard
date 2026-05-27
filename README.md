# PhishGuard 🛡️
### Phishing Awareness Training Platform

A web-based security training tool that simulates realistic phishing emails and trains users to identify threats before they click. Built with Python (Flask) and SQLite.

> **Why this exists:** Human error causes over 90% of data breaches. PhishGuard trains employees to spot phishing attempts through hands-on scenario practice — the same approach used by enterprise platforms like KnowBe4 and Proofpoint Security Awareness.

---

## Demo

| Login | Dashboard | Quiz |
|---|---|---|
| Session-based auth with hashed passwords | Awareness score, difficulty breakdown, pending scenarios | Realistic email viewer with red-flag checklist and live timer |

**Try it yourself** → [Setup instructions below](#quick-start)

---

## Features

- **Realistic email scenarios** — 6 phishing templates across Easy / Medium / Hard difficulty, covering credential theft, business email compromise, impersonation, and prize scams
- **Interactive quiz interface** — fake email client UI, collapsible red-flag checklist, live timer, instant feedback
- **Awareness scoring** — per-user score tracking with difficulty breakdown (easy/medium/hard)
- **Admin reports panel** — organisation-wide stats, per-employee performance table, scenario success rates, recent activity feed
- **Session-based authentication** — secure login with werkzeug PBKDF2 password hashing
- **SQLite persistence** — lightweight database, zero configuration needed

---

## Security Concepts Demonstrated

This project directly applies the following cybersecurity concepts:

| Concept | Implementation |
|---|---|
| **Phishing awareness** | 6 scenarios covering typosquatting, BEC, impersonation, urgency tactics |
| **Secure password storage** | PBKDF2 hashing via `werkzeug.security` (salted, not plain SHA-256) |
| **Session management** | Flask server-side sessions with secret key |
| **Role-based access control** | Employee vs Admin roles with protected routes |
| **Social engineering education** | Each scenario explains the specific manipulation technique used |

---

## Quick Start

### Requirements
- Python 3.8+
- pip

### Run on Mac / Linux
```bash
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
bash start.sh
```

### Run on Windows
```
git clone https://github.com/YOUR_USERNAME/phishguard.git
cd phishguard
start.bat
```

### Run manually
```bash
pip install -r requirements.txt
python app.py
```

Then open your browser at: **http://localhost:5050**

---

## Demo Accounts

| Role | Email | Password |
|---|---|---|
| Admin | admin@company.com | admin123 |
| Employee | alice@company.com | password123 |
| Employee | bob@company.com | password123 |
| Employee | carol@company.com | password123 |
| Employee | dave@company.com | password123 |

---

## Project Structure

```
phishguard/
├── app.py                  ← Flask server — routes, auth, database logic
├── requirements.txt        ← Python dependencies
├── start.sh                ← Mac/Linux launcher
├── start.bat               ← Windows launcher
├── training.db             ← SQLite database (auto-created on first run)
└── templates/
    ├── login.html          ← Login page
    ├── dashboard.html      ← User dashboard with stats and scenario list
    ├── quiz.html           ← Email viewer + red flag checklist + verdict
    └── reports.html        ← Admin-only analytics panel
```

---

## Scenario Library

| Scenario | Difficulty | Category | Key Red Flag |
|---|---|---|---|
| IT Password Reset | Easy | Credential Theft | Typosquatted domain (`comp4ny.com`) |
| Free Amazon Gift Card | Easy | Prize Scam | Fake domain + artificial scarcity |
| Microsoft 365 Login Alert | Medium | Impersonation | `microsoft-accounts-alert.com` ≠ `microsoft.com` |
| CEO Wire Transfer Request | Medium | Business Email Compromise | Lookalike domain + secrecy instruction |
| DocuSign Contract Review | Hard | Credential Theft | Subdomain trick (`docusign.net-signing-portal.com`) |
| HR Benefits Enrollment | Hard | Credential Theft | Timed to real company event cycle |

---

## Resetting the Database

```bash
bash start.sh --reset     # Mac/Linux
start.bat --reset         # Windows
```

---

## Roadmap

- [ ] Add legitimate (non-phishing) email scenarios for mixed training
- [ ] Email report export for admins (PDF)
- [ ] Leaderboard across employees
- [ ] More scenario categories (SMS smishing, QR code phishing)

---

## Disclaimer

PhishGuard is a **purely educational tool**. No real emails are sent. All phishing scenarios are fictional and exist solely to train users to identify threats. This project is intended for security awareness training purposes only.

---

## Author

**Sotonwa Jonathan**  
Cybersecurity Analyst (in training) | CS Student @ Ajayi Crowther University  
[LinkedIn](www.linkedin.com/in/sotonwa-jonathan-9aa210412) · [TryHackMe](https://tryhackme.com/p/sotonwajonathan1
)

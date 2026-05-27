"""
PhishGuard – Phishing Awareness Training Platform
A web-based tool to train employees to identify phishing emails.
NO actual emails are sent. All content is educational and displayed in-browser only.
"""

from flask import (
    Flask, render_template, request, jsonify,
    session, redirect, url_for
)
import sqlite3
import json
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-in-production-use-64char-random")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training.db")


# ─────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS employees (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                email      TEXT NOT NULL UNIQUE,
                department TEXT NOT NULL DEFAULT 'General',
                password   TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'employee',
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS scenarios (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                title        TEXT NOT NULL,
                difficulty   TEXT NOT NULL DEFAULT 'medium',
                category     TEXT NOT NULL DEFAULT 'generic',
                sender_name  TEXT NOT NULL,
                sender_email TEXT NOT NULL,
                subject      TEXT NOT NULL,
                body_html    TEXT NOT NULL,
                red_flags    TEXT NOT NULL,
                created_at   TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS quiz_attempts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id    INTEGER NOT NULL REFERENCES employees(id),
                scenario_id    INTEGER NOT NULL REFERENCES scenarios(id),
                user_said_phish INTEGER NOT NULL,
                is_correct     INTEGER NOT NULL,
                flags_spotted  TEXT NOT NULL DEFAULT '[]',
                time_taken_sec INTEGER NOT NULL DEFAULT 0,
                attempted_at   TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        if db.execute("SELECT COUNT(*) FROM employees").fetchone()[0] == 0:
            _seed(db)
        db.commit()


def _hash(pw):
    return generate_password_hash(pw)


def _check_hash(pw, hashed):
    return check_password_hash(hashed, pw)


def _seed(db):
    db.execute("INSERT INTO employees (name,email,department,password,role) VALUES (?,?,?,?,?)",
               ("Admin User","admin@company.com","IT Security",_hash("admin123"),"admin"))
    for name, email, dept in [
        ("Alice Johnson","alice@company.com","Finance"),
        ("Bob Smith","bob@company.com","Marketing"),
        ("Carol White","carol@company.com","HR"),
        ("Dave Brown","dave@company.com","Engineering"),
    ]:
        db.execute("INSERT INTO employees (name,email,department,password,role) VALUES (?,?,?,?,?)",
                   (name, email, dept, _hash("password123"), "employee"))

    scenarios = [
        {
            "title": "IT Password Reset",
            "difficulty": "easy",
            "category": "Credential Theft",
            "sender_name": "IT Support",
            "sender_email": "it-support@comp4ny.com",
            "subject": "URGENT: Your password expires in 24 hours!",
            "body_html": """<p>Dear Employee,</p>
<p>Our system has detected that your corporate password will <strong>EXPIRE IN 24 HOURS</strong>.</p>
<p>To avoid losing access to all company systems, please click the link below <strong>immediately</strong>:</p>
<p style="text-align:center;margin:24px 0">
  <a href="#" style="background:#cc0000;color:#fff;padding:12px 28px;border-radius:4px;text-decoration:none;font-weight:bold;font-size:15px;">RESET PASSWORD NOW</a>
</p>
<p>If you do not reset your password within 24 hours, your account will be <strong>permanently locked</strong>.</p>
<p>Best regards,<br><strong>IT Support Team</strong><br>Company Corp</p>""",
            "red_flags": json.dumps([
                "Sender domain 'comp4ny.com' uses the number 4 instead of the letter 'a' — a classic typosquatting trick to mimic your real company domain.",
                "Extreme urgency ('URGENT', '24 hours', 'EXPIRE') is designed to panic you into clicking before thinking.",
                "Threatening permanent account lockout is a scare tactic — IT never permanently locks accounts via email.",
                "Legitimate IT departments never ask you to click an email link to reset your password. Always use your company's official self-service portal.",
                "Generic greeting ('Dear Employee') — real internal IT emails know your name."
            ])
        },
        {
            "title": "Free Amazon Gift Card",
            "difficulty": "easy",
            "category": "Prize Scam",
            "sender_name": "Amazon Rewards",
            "sender_email": "noreply@amazon-rewards-giftcards.net",
            "subject": "You've been selected for a $500 Amazon Gift Card! 🎁",
            "body_html": """<p>Congratulations! You have been <strong>randomly selected</strong> as one of our 5 lucky winners this month!</p>
<p style="font-size:1.3em;color:green;font-weight:bold;margin:16px 0">🎁 Your Reward: $500 Amazon Gift Card</p>
<p>To claim your prize, simply complete a short 2-minute survey and confirm your shipping address.</p>
<p style="background:#fff3cd;border:1px solid #ffc107;padding:10px;margin:12px 0">⚠️ <strong>This offer expires in 1 hour.</strong> Only 3 prizes remain unclaimed!</p>
<p><a href="#" style="color:#e47911;font-weight:bold;font-size:1.1em">→ CLAIM MY $500 GIFT CARD</a></p>
<p>Amazon Customer Rewards Team</p>""",
            "red_flags": json.dumps([
                "You never entered any contest — unsolicited prizes are a hallmark of phishing and scam emails.",
                "Sender domain 'amazon-rewards-giftcards.net' is NOT amazon.com. Real Amazon emails come from @amazon.com only.",
                "Artificial scarcity ('only 3 prizes left', 'expires in 1 hour') stops you thinking critically.",
                "Requesting personal info via a 'survey' and 'shipping address' is a data-harvesting technique.",
                "Excessive emojis, all-caps, and exclamation marks are common signals of spam and phishing."
            ])
        },
        {
            "title": "Microsoft 365 Login Alert",
            "difficulty": "medium",
            "category": "Impersonation",
            "sender_name": "Microsoft Account Team",
            "sender_email": "security@microsoft-accounts-alert.com",
            "subject": "Unusual sign-in activity detected on your account",
            "body_html": """<p>Dear Microsoft 365 User,</p>
<p>We detected a sign-in attempt to your Microsoft account from an unusual location:</p>
<table style="border-collapse:collapse;width:100%;margin:16px 0;font-size:14px">
  <tr style="background:#f3f3f3"><td style="padding:10px 14px;border:1px solid #ddd;font-weight:600">Location</td><td style="padding:10px 14px;border:1px solid #ddd">Lagos, Nigeria</td></tr>
  <tr><td style="padding:10px 14px;border:1px solid #ddd;font-weight:600">IP Address</td><td style="padding:10px 14px;border:1px solid #ddd">197.210.84.117</td></tr>
  <tr style="background:#f3f3f3"><td style="padding:10px 14px;border:1px solid #ddd;font-weight:600">Time</td><td style="padding:10px 14px;border:1px solid #ddd">Today at 3:41 AM</td></tr>
  <tr><td style="padding:10px 14px;border:1px solid #ddd;font-weight:600">Device</td><td style="padding:10px 14px;border:1px solid #ddd">Unknown Windows PC</td></tr>
</table>
<p>If this was not you, your account may be compromised. Please verify your identity immediately:</p>
<p style="text-align:center;margin:20px 0">
  <a href="#" style="background:#0078d4;color:white;padding:12px 28px;border-radius:3px;text-decoration:none;font-weight:600">Verify My Account</a>
</p>
<p>If you do not verify within <strong>12 hours</strong>, your account will be suspended for security.</p>
<p>Microsoft Security Team<br>Microsoft Corporation</p>""",
            "red_flags": json.dumps([
                "Sender domain 'microsoft-accounts-alert.com' is NOT microsoft.com. Real Microsoft security emails come from @microsoft.com only.",
                "The unusual location (Lagos, Nigeria) triggers emotional panic — this is deliberate social engineering.",
                "Hovering over 'Verify My Account' reveals a non-Microsoft URL. Never click links without checking the destination.",
                "Microsoft never threatens account suspension via email with a verify link. Always go to account.microsoft.com directly.",
                "The 12-hour deadline is pure pressure tactic — legitimate security alerts don't work this way."
            ])
        },
        {
            "title": "CEO Wire Transfer Request",
            "difficulty": "medium",
            "category": "Business Email Compromise",
            "sender_name": "Jennifer Walsh (CEO)",
            "sender_email": "j.walsh@company-corp.net",
            "subject": "Confidential – Urgent wire transfer needed",
            "body_html": """<p>Hi,</p>
<p>I'm in a board meeting and cannot take calls right now. I need you to process an urgent wire transfer — it is time-sensitive and must be completed before end of business today.</p>
<p style="margin:16px 0;padding:14px;background:#f9f9f9;border-left:3px solid #ccc">
  <strong>Amount:</strong> $47,500<br>
  <strong>Beneficiary:</strong> Meridian Consulting LLC<br>
  <strong>Account:</strong> 8823-001-7741<br>
  <strong>Routing:</strong> 021000089
</p>
<p>Please keep this confidential — we are under NDA for an acquisition. I'll explain at tomorrow's all-hands.</p>
<p>Process it and confirm back to me via email. <strong>Do NOT discuss with anyone else yet.</strong></p>
<p>Thanks,<br>Jennifer</p>""",
            "red_flags": json.dumps([
                "The CEO's real email is '@company.com', not '@company-corp.net'. This lookalike domain is a classic Business Email Compromise (BEC) tactic.",
                "BEC attacks impersonating executives are one of the most costly forms of cybercrime, costing businesses billions annually.",
                "The confidentiality instruction ('tell no one') deliberately blocks you from verifying the request with colleagues.",
                "Claiming to be unavailable by phone removes your ability to call and confirm. Always verify large transfers by phone.",
                "The end-of-day urgency bypasses your company's normal multi-approval wire transfer process.",
                "Legitimate wire transfers always require documented, multi-person approval — never act on a single email alone."
            ])
        },
        {
            "title": "DocuSign Contract Review",
            "difficulty": "hard",
            "category": "Credential Theft",
            "sender_name": "DocuSign via Company Legal",
            "sender_email": "dse@docusign.net-signing-portal.com",
            "subject": "Please review and sign: NDA Agreement – Action Required",
            "body_html": """<div style="font-family:Arial,sans-serif">
  <div style="background:#1b4fac;padding:14px 22px">
    <span style="font-size:1.4em;font-weight:bold;color:#fff">DocuSign</span>
    <span style="color:rgba(255,255,255,.7);font-size:.85em;margin-left:8px">eSignature</span>
  </div>
  <div style="padding:28px;border:1px solid #e0e0e0;border-top:none">
    <p style="color:#333"><strong>Company Legal Department</strong> has sent you a document for review and signature.</p>
    <p style="margin:14px 0;color:#555;font-size:14px">
      <strong>Document:</strong> Mutual Non-Disclosure Agreement v3.2<br>
      <strong>Sign by:</strong> Today at 5:00 PM<br>
      <strong>Message:</strong> <em>"Please sign before our partner call this afternoon."</em>
    </p>
    <p style="text-align:center;margin:24px 0">
      <a href="#" style="background:#1b4fac;color:#fff;padding:14px 32px;border-radius:4px;text-decoration:none;font-weight:bold;font-size:15px">REVIEW DOCUMENT</a>
    </p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
    <p style="font-size:12px;color:#999">Do not share this link. Expires in 24 hours.<br>Powered by DocuSign | 221 Main St, San Francisco, CA<br><a href="#" style="color:#999">Unsubscribe</a></p>
  </div>
</div>""",
            "red_flags": json.dumps([
                "Sender 'docusign.net-signing-portal.com': here 'docusign.net' is a subdomain of 'signing-portal.com' (a fake domain). Real DocuSign sends from @docusign.com or docusign.net (without anything after .net).",
                "Hovering over 'REVIEW DOCUMENT' reveals a non-DocuSign URL — always check links before clicking.",
                "Time pressure ('5 PM today') with a plausible business context ('partner call') is calculated social engineering.",
                "Legitimate DocuSign links always contain 'docusign.com' in the actual domain portion of the URL.",
                "Never enter your SSO credentials after clicking an email link. Log in to DocuSign directly at docusign.com and check for pending documents there.",
                "Verify unexpected contract requests with the Legal team directly via Teams, phone, or a fresh email — not by replying to the suspicious email."
            ])
        },
        {
            "title": "HR Open Enrollment Deadline",
            "difficulty": "hard",
            "category": "Credential Theft",
            "sender_name": "Human Resources – Benefits Team",
            "sender_email": "benefits-enrollment@company-hr-portal.com",
            "subject": "Benefits Open Enrollment Closes This Friday – Action Required",
            "body_html": """<p>Dear Team Member,</p>
<p>This is a reminder that <strong>Open Enrollment closes this Friday at 5:00 PM</strong>. If you do not complete your selections, you will be enrolled in the default plan which may not cover your current providers.</p>
<p>To review and update your 2025 benefits:</p>
<ol style="margin:14px 0 14px 20px;line-height:2">
  <li>Click the secure link below to access the Benefits Portal</li>
  <li>Log in with your company Single Sign-On (SSO) credentials</li>
  <li>Review and confirm your 2025 elections before Friday</li>
</ol>
<p><a href="#" style="color:#1a73e8;font-weight:500;font-size:15px">→ Access the 2025 Benefits Enrollment Portal</a></p>
<p>Questions? Contact <a href="mailto:benefits@company.com">benefits@company.com</a> or call ext. 4400.</p>
<p>Best regards,<br><strong>Sarah Mitchell</strong><br>HR Benefits Coordinator<br>Company Corp | (555) 234-7890</p>""",
            "red_flags": json.dumps([
                "Sender domain 'company-hr-portal.com' is NOT company.com. Adding '-hr-portal' is a common lookalike domain trick.",
                "This email asks for SSO (Single Sign-On) credentials — the master key to all company systems, making it an extremely high-value target.",
                "The scenario is timed to match a real, predictable company event (benefits season), making it very convincing.",
                "Always hover over links to verify the URL matches your known HR portal exactly. One extra word in the domain means it's fake.",
                "Never click email links for SSO logins. Navigate to the HR portal by typing the URL yourself or via your company intranet.",
                "When in doubt, call HR directly at ext. 4400 or email benefits@company.com from your own email client to verify."
            ])
        },
    ]
    for s in scenarios:
        db.execute(
            "INSERT INTO scenarios (title,difficulty,category,sender_name,sender_email,subject,body_html,red_flags) VALUES (?,?,?,?,?,?,?,?)",
            (s["title"],s["difficulty"],s["category"],s["sender_name"],s["sender_email"],s["subject"],s["body_html"],s["red_flags"])
        )


# ─────────────────────────────────────────────────────────────
# Auth decorator
# ─────────────────────────────────────────────────────────────

def require_login(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ─────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        email    = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        with get_db() as db:
            user = db.execute(
                "SELECT * FROM employees WHERE lower(email)=?",
                (email,)
            ).fetchone()
        if user and _check_hash(password, user["password"]):
            session.clear()
            session["user_id"]   = user["id"]
            session["user_name"] = user["name"]
            session["user_role"] = user["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid email or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@require_login
def dashboard():
    uid = session["user_id"]
    with get_db() as db:
        attempts = db.execute("""
            SELECT qa.*, s.title, s.difficulty, s.category
            FROM quiz_attempts qa
            JOIN scenarios s ON s.id = qa.scenario_id
            WHERE qa.employee_id = ?
            ORDER BY qa.attempted_at DESC
        """, (uid,)).fetchall()

        all_scenarios = db.execute("""
            SELECT * FROM scenarios
            ORDER BY CASE difficulty WHEN 'easy' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, id
        """).fetchall()

    total   = len(attempts)
    correct = sum(1 for a in attempts if a["is_correct"])
    score   = round(correct / total * 100) if total else 0

    # Use a plain Python set for reliable 'in' checks in Jinja
    attempted_ids = {a["scenario_id"] for a in attempts}
    pending = [s for s in all_scenarios if s["id"] not in attempted_ids]

    # Per-difficulty stats computed in Python
    breakdown = {}
    for diff in ("easy", "medium", "hard"):
        sub = [a for a in attempts if a["difficulty"] == diff]
        n, c = len(sub), sum(1 for a in sub if a["is_correct"])
        breakdown[diff] = {"total": n, "correct": c, "pct": round(c / n * 100) if n else 0}

    return render_template("dashboard.html",
        attempts=attempts,
        all_scenarios=all_scenarios,
        attempted_ids=attempted_ids,
        pending=pending,
        total=total, correct=correct, score=score,
        breakdown=breakdown,
    )


@app.route("/quiz/<int:scenario_id>")
@require_login
def quiz(scenario_id):
    with get_db() as db:
        scenario = db.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not scenario:
            return redirect(url_for("dashboard"))
        existing = db.execute(
            "SELECT * FROM quiz_attempts WHERE employee_id=? AND scenario_id=?",
            (session["user_id"], scenario_id)
        ).fetchone()
    return render_template("quiz.html",
        scenario=scenario,
        red_flags=json.loads(scenario["red_flags"]),
        existing=existing,
        spotted_flags=json.loads(existing["flags_spotted"]) if existing else [],
    )


@app.route("/api/submit", methods=["POST"])
@require_login
def api_submit():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    scenario_id    = int(data.get("scenario_id", 0))
    user_phishing  = int(data.get("is_phishing", 0))
    flags_spotted  = data.get("flags_spotted", [])
    time_taken     = int(data.get("time_taken", 0))
    uid = session["user_id"]

    with get_db() as db:
        scenario = db.execute("SELECT * FROM scenarios WHERE id=?", (scenario_id,)).fetchone()
        if not scenario:
            return jsonify({"error": "Scenario not found"}), 404

        existing = db.execute(
            "SELECT is_correct FROM quiz_attempts WHERE employee_id=? AND scenario_id=?",
            (uid, scenario_id)
        ).fetchone()

        if existing:
            # FIX: return the STORED result, never let a second submit change the score
            is_correct = existing["is_correct"]
        else:
            # All demo scenarios ARE phishing; correct = user said phishing
            is_correct = 1 if user_phishing == 1 else 0
            db.execute("""
                INSERT INTO quiz_attempts
                    (employee_id, scenario_id, user_said_phish, is_correct, flags_spotted, time_taken_sec)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (uid, scenario_id, user_phishing, is_correct,
                  json.dumps(flags_spotted), time_taken))
            db.commit()

    return jsonify({
        "is_correct":        is_correct,
        "user_said_phish":   user_phishing,
        "explanation":       json.loads(scenario["red_flags"]),
        "difficulty":        scenario["difficulty"],
        "already_attempted": existing is not None,
    })


@app.route("/admin/reports")
@require_login
def admin_reports():
    if session.get("user_role") != "admin":
        return redirect(url_for("dashboard"))

    with get_db() as db:
        employees = db.execute("""
            SELECT
                e.id, e.name, e.email, e.department,
                COUNT(qa.id)                                              AS total_attempts,
                COALESCE(SUM(qa.is_correct), 0)                          AS total_correct,
                CASE WHEN COUNT(qa.id) > 0
                     THEN ROUND(SUM(qa.is_correct) * 100.0 / COUNT(qa.id), 1)
                     ELSE NULL END                                        AS score_pct
            FROM employees e
            LEFT JOIN quiz_attempts qa ON qa.employee_id = e.id
            WHERE e.role = 'employee'
            GROUP BY e.id
            ORDER BY score_pct DESC
        """).fetchall()

        scenarios = db.execute("""
            SELECT
                s.id, s.title, s.difficulty, s.category,
                COUNT(qa.id)                                              AS total_attempts,
                CASE WHEN COUNT(qa.id) > 0
                     THEN ROUND(SUM(qa.is_correct) * 100.0 / COUNT(qa.id), 1)
                     ELSE NULL END                                        AS success_rate
            FROM scenarios s
            LEFT JOIN quiz_attempts qa ON qa.scenario_id = s.id
            GROUP BY s.id
            ORDER BY success_rate ASC
        """).fetchall()

        recent = db.execute("""
            SELECT qa.is_correct, qa.user_said_phish, qa.attempted_at,
                   e.name AS emp_name, s.title AS scenario_title, s.difficulty
            FROM quiz_attempts qa
            JOIN employees e ON e.id = qa.employee_id
            JOIN scenarios  s ON s.id = qa.scenario_id
            ORDER BY qa.attempted_at DESC LIMIT 30
        """).fetchall()

    # FIX: compute avg in Python, not Jinja, to avoid sqlite Row filter issues
    trained = [e for e in employees if e["total_attempts"] and e["total_attempts"] > 0]
    avg_score = round(sum(e["score_pct"] for e in trained) / len(trained), 1) if trained else 0

    return render_template("reports.html",
        employees=employees,
        scenarios=scenarios,
        recent=recent,
        avg_score=avg_score,
        trained_count=len(trained),
    )


if __name__ == "__main__":
    init_db()
    print("\n  PhishGuard at http://localhost:5050")
    print("  Admin:    admin@company.com / admin123")
    print("  Employee: alice@company.com / password123\n")
    app.run(debug=True, port=5050)

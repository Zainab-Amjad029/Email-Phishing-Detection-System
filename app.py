from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    send_file
)

import sqlite3
import csv
import joblib
import os
import re
import shutil
from io import BytesIO

from functools import wraps

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

import PyPDF2
import pdfplumber

try:
    import fitz
except ImportError:
    fitz = None

try:
    import pytesseract
except ImportError:
    pytesseract = None

from PIL import Image
from phishing_analyzer import analyze_email
from pdf_report import generate_scan_pdf
from ai_detector import ai_detect_email
from header_analyzer import HeaderAnalyzer

app = Flask(__name__)
app.secret_key = "infosec_project_secret"

# Feature flag: enable/disable advanced AI at runtime
AI_ENABLED = os.getenv('AI_ENABLED', 'false').lower() == 'true'


# ==================================================
# LOAD MODEL
# ==================================================

pipeline = None
try:
    pipeline = joblib.load("models/phishing_pipeline.pkl")
    model = pipeline.named_steps["classifier"]
    vectorizer = pipeline.named_steps["vectorizer"]
except Exception:
    model = joblib.load("models/phishing_model.pkl")
    vectorizer = joblib.load("models/vectorizer.pkl")


def _sanitize_email_text(text):
    if not text:
        return ""

    lines = []
    header_pattern = re.compile(
        r"^\s*(from|to|subject|date|message-id|mime-version|content-type|content-transfer-encoding|content-disposition|boundary|x-[\w-]+)\s*:",
        re.IGNORECASE,
    )
    ignore_tokens = re.compile(
        r"\b(utf-8|utf8|charset|quoted-printable|base64|multipart|boundary|content-type|content-disposition|mime-version|us-ascii|iso-8859-1|windows-1252|plain|html)\b",
        re.IGNORECASE,
    )

    for line in str(text).splitlines():
        if header_pattern.match(line):
            continue
        if ignore_tokens.search(line) and len(line.split()) <= 6:
            continue
        lines.append(line)

    sanitized = "\n".join(lines)
    sanitized = re.sub(r"\b(utf-8|utf8|charset|quoted-printable|base64|iso-8859-1|windows-1252|us-ascii)\b", " ", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"[<>\\]|=+", " ", sanitized)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()
    return sanitized


def _extract_header_value(text, header_name):
    match = re.search(rf"^{header_name}\s*:\s*(.+)$", text, flags=re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else None


def _extract_sender_receiver(text):
    sender = _extract_header_value(text, "from")
    receiver = _extract_header_value(text, "to")

    if sender:
        sender = sender.split("<")[-1].split(">")[0].strip()
    if receiver:
        receiver = receiver.split("<")[-1].split(">")[0].strip()

    return sender or "Unknown", receiver or "Unknown"


def _get_mail_excerpt(text, max_chars=220):
    body = re.sub(r"(?m)^(from|to|subject|date|message-id|mime-version|content-type|content-transfer-encoding|content-disposition|boundary|x-[\w-]+)\s*:\s*.*$", "", text)
    body = re.sub(r"\s+", " ", body).strip()
    if len(body) <= max_chars:
        return body
    return body[:max_chars].strip() + "..."


def _format_reason(reason):
    reason = str(reason).strip()
    if not reason:
        return reason
    if reason[-1] not in ".!?":
        return reason + "."
    return reason


def _append_model_reasons(reasons, prediction, result, phishing_prob, risk_score):
    if prediction == 1:
        reasons.append(
            f"The machine learning model detected wording patterns commonly found in phishing emails and assigned a phishing score of {round(phishing_prob * 100, 2)}%."
        )
        if result == "SAFE":
            reasons.append(
                "The combined assessment remained SAFE because the overall risk score was below the phishing threshold."
            )
        else:
            reasons.append(
                "Multiple factors pushed the combined risk high enough to classify this email as PHISHING."
            )
    else:
        reasons.append(
            f"The machine learning model found this email more similar to legitimate messages with a phishing score of {round(phishing_prob * 100, 2)}%."
        )
        if result == "PHISHING":
            reasons.append(
                "Additional rule-based and header checks raised the overall risk, resulting in a PHISHING classification."
            )


def _humanize_reason_text(reason):
    reason = str(reason).strip()
    if not reason:
        return reason

    replacements = [
        (r"^Contains suspicious phrase: '(.+)' - This is typically used to trick you into taking action$",
         r"Suspicious phrase detected: '\1' is often used to trick recipients."),
        (r"^Contains suspicious word: '(.+)' - Commonly used in phishing to create urgency$",
         r"Suspicious word detected: '\1' is often used to create urgency."),
        (r"^Contains links - Be careful! Phishing emails often contain malicious links$",
         r"Contains links, which is common in phishing emails."),
        (r"^Uses shortened URL \((.+)\) - Links can be hidden to disguise their true destination$",
         r"Uses a shortened URL (\1), which can hide the destination."),
        (r"^URL uses suspicious country domain \((.+)\) - High-risk region: (.+)$",
         r"URL domain appears to be from a higher-risk region: \1."),
        (r"^Contains link text \(www\.\.\.\) without actual clickable link - Designed to trick you into typing in the address$",
         r"Contains plain website text instead of a proper clickable link."),
        (r"^Asks for your passwords or personal info - Legitimate companies will never ask this via email$",
         r"Requests personal or password information, which legitimate companies rarely ask for by email."),
        (r"^Uses urgent/pressure language - Scammers create fake urgency to rush you into clicking malicious links$",
         r"Uses urgent or pressure language to try to rush you into action."),
        (r"^Email appears genuine - Uses personal, polite wording typical of legitimate messages$",
         r"Uses personal, polite wording, which is more characteristic of legitimate emails."),
        (r"^Multiple exclamation marks - Phishing emails use excessive punctuation to look urgent$",
         r"Contains many exclamation marks, which can make the email feel more urgent."),
        (r"^Written in ALL-CAPS - Phishing emails often use ALL CAPS to look important and urgent$",
         r"Uses ALL CAPS, which is often a sign of suspicious messaging."),
        (r"^Uses generic greeting \(Dear Customer/User\) - Real companies address you by name$",
         r"Uses a generic greeting instead of your name."),
        (r"^Asks you to click or visit a link - Don't click links in suspicious emails$",
         r"Asks you to click or visit a link, which is a common phishing tactic."),
        (r"^Suspicious promotional offer - 'You won!' and 'Free offer!' emails are common phishing tactics$",
         r"Contains promotional language like 'You won!', which is commonly used in scams."),
        (r"^Email contains legitimate banking language - Appears to be from your actual bank$",
         r"Includes banking language, which can make the email appear more legitimate."),
        (r"^Advanced AI predicted phishing \((.+)% confidence\)$",
         r"An additional AI check predicted phishing with \1% confidence."),
        (r"^Advanced AI predicted safe email \((.+)% confidence\)$",
         r"An additional AI check predicted the email is safe with \1% confidence."),
        (r"^Note: URL reputation check unavailable \((.+)\.\.\.\)$",
         r"Note: URL reputation check was unavailable (\1...)."),
        (r"^WARNING: No SPF record for (.+) - This is a red flag for spoofing$",
         r"No SPF record found for \1, which makes sender spoofing easier."),
        (r"^WARNING: No DMARC policy for (.+) - This email passed through a mail system without proper verification$",
         r"No DMARC policy found for \1, reducing email authentication assurance."),
        (r"^GOOD: SPF record found - helps prevent sender spoofing$",
         r"SPF authenticated successfully, which helps confirm the sender."),
        (r"^GOOD: DKIM digital signature found - email is cryptographically signed$",
         r"DKIM signature is valid, indicating the email was signed by the sender's domain."),
        (r"^No clear phishing indicators found$",
         r"No clear phishing indicators were found."),
    ]

    for pattern, replacement in replacements:
        new_reason = re.sub(pattern, replacement, reason, flags=re.IGNORECASE)
        if new_reason != reason:
            reason = new_reason
            break

    if reason[-1] not in ".!?":
        reason += "."
    return reason


def get_model_explanations(text, vectorizer, model, top_n=5):
    """Return a list of human-readable model contribution reasons.

    Works best for linear models (LogisticRegression). For tree models,
    falls back to feature importances.
    """
    try:
        X = vectorizer.transform([text])
    except Exception:
        return []

    reasons = []

    normalized_text = re.sub(r"[^a-z0-9\s]", " ", text.lower())
    normalized_text = re.sub(r"\s+", " ", normalized_text).strip()
    word_tokens = set(normalized_text.split())

    def normalize_feature_name(name):
        if "__" in name:
            name = name.split("__", 1)[1]
        return name.replace("_", " ").strip()

    def feature_in_text(feature_name):
        normalized = normalize_feature_name(feature_name).lower()
        if not normalized or normalized.isdigit():
            return False
        if " " in normalized:
            return normalized in normalized_text
        return normalized in word_tokens

    def readable_feature(name):
        normalized = normalize_feature_name(name)
        normalized_lower = normalized.lower()
        ignore_tokens = [
            "utf",
            "utf-8",
            "utf8",
            "charset",
            "base64",
            "quoted",
            "printable",
            "mime",
            "content",
            "type",
            "multipart",
            "boundary",
            "iso",
            "windows",
            "ascii",
            "plain",
            "html",
        ]
        if any(token in normalized_lower for token in ignore_tokens):
            return False
        return bool(re.search(r"[a-zA-Z]{3,}", normalized))

    def describe_strength(weight):
        abs_weight = abs(weight)
        if abs_weight >= 0.3:
            return "strongly"
        if abs_weight >= 0.15:
            return "moderately"
        return "slightly"

    try:
        coef = None
        if hasattr(model, "coef_"):
            coef = model.coef_.ravel()
        elif hasattr(model, "feature_importances_"):
            import numpy as _np
            feats = model.feature_importances_
            top_idx = _np.argsort(feats)[-top_n:][::-1]
            feature_names = vectorizer.get_feature_names_out()

            for i in top_idx:
                feature = feature_names[i]
                if not readable_feature(feature):
                    continue
                if not feature_in_text(feature):
                    continue
                normalized = normalize_feature_name(feature)
                reasons.append(f"ML model found the term '{normalized}' as an important signal")

            if not reasons:
                reasons.append("ML model detected important wording patterns in the email")
            return reasons

        if coef is None:
            return []

        import numpy as np

        xarr = X.toarray().ravel()
        contrib = xarr * coef

        if np.all(contrib == 0):
            return []

        feature_names = vectorizer.get_feature_names_out()
        nonzero_idx = np.where(xarr != 0)[0]
        if nonzero_idx.size == 0:
            return []

        contrib_nonzero = [(i, contrib[i]) for i in nonzero_idx]
        contrib_nonzero.sort(key=lambda t: abs(t[1]), reverse=True)

        for idx, val in contrib_nonzero:
            if len(reasons) >= top_n:
                break
            feature = feature_names[idx]
            if not readable_feature(feature):
                continue
            if not feature_in_text(feature):
                continue
            normalized = normalize_feature_name(feature)
            strength = describe_strength(val)
            if val > 0:
                reasons.append(
                    f"ML signal: the term '{normalized}' was present and {strength} increased phishing likelihood."
                )
            else:
                reasons.append(
                    f"ML signal: the term '{normalized}' was present and {strength} increased safe likelihood."
                )

        if not reasons:
            reasons.append("ML model detected wording patterns relevant to the decision")

        return reasons
    except Exception:
        return []



# ==================================================
# LOGIN REQUIRED
# ==================================================

def login_required(f):

    @wraps(f)

    def decorated_function(*args, **kwargs):

        if "user_id" not in session:

            return redirect("/login")

        return f(*args, **kwargs)

    return decorated_function


def _extract_text_from_pdf(data):
    text_blocks = []

    try:
        reader = PyPDF2.PdfReader(BytesIO(data))
        for page in reader.pages:
            text = page.extract_text()
            if text:
                text_blocks.append(text)
    except Exception:
        pass

    if text_blocks:
        return "\n".join(text_blocks).strip()

    try:
        with pdfplumber.open(BytesIO(data)) as pdf:
            for page in pdf.pages:
                text = page.extract_text()
                if text:
                    text_blocks.append(text)
    except Exception:
        pass

    if text_blocks:
        return "\n".join(text_blocks).strip()

    if fitz is not None:
        try:
            pdf_document = fitz.open(stream=data, filetype="pdf")
            for page in pdf_document:
                text = page.get_text("text") or page.get_text("blocks")
                if text:
                    text_blocks.append(text)
        except Exception:
            pass

    if text_blocks:
        return "\n".join(text_blocks).strip()

    ocr_text = _extract_text_from_pdf_ocr(data)
    return ocr_text if ocr_text else None


def _extract_text_from_pdf_ocr(data):
    if fitz is None or pytesseract is None:
        return None

    if shutil.which("tesseract") is None:
        return None

    pages = []
    try:
        pdf_document = fitz.open(stream=data, filetype="pdf")
        for page in pdf_document:
            pix = page.get_pixmap(dpi=300)
            mode = "RGB" if pix.alpha == 0 else "RGBA"
            image = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
            text = pytesseract.image_to_string(image)
            if text:
                pages.append(text)
    except Exception:
        return None

    return "\n".join(pages).strip() if pages else None


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if "user_id" in session:

        return redirect("/dashboard")

    return redirect("/login")


# ==================================================
# REGISTER
# ==================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form["username"]

        email = request.form["email"]

        password = generate_password_hash(
            request.form["password"]
        )

        conn = sqlite3.connect(
            "phishing.db"
        )

        cursor = conn.cursor()

        try:

            cursor.execute("""
            INSERT INTO users
            (
                username,
                email,
                password
            )
            VALUES(?,?,?)
            """,
            (
                username,
                email,
                password
            ))

            conn.commit()

            conn.close()

            return redirect("/login")

        except sqlite3.IntegrityError:

            conn.close()

            return "Email already exists"

    return render_template(
        "register.html"
    )


# ==================================================
# LOGIN
# ==================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        email = request.form["email"]

        password = request.form["password"]

        conn = sqlite3.connect(
            "phishing.db"
        )

        cursor = conn.cursor()

        cursor.execute("""
        SELECT *
        FROM users
        WHERE email=?
        """,
        (email,)
        )

        user = cursor.fetchone()

        conn.close()

        if user and check_password_hash(
            user[3],
            password
        ):

            session["user_id"] = user[0]

            session["username"] = user[1]

            return redirect(
                "/dashboard"
            )

        return "Invalid email or password"

    return render_template(
        "login.html"
    )


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
@login_required
def dashboard():

    conn = sqlite3.connect(
        "phishing.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM scans"
    )

    total = cursor.fetchone()[0]

    cursor.execute("""
    SELECT COUNT(*)
    FROM scans
    WHERE prediction='PHISHING'
    """)

    phishing = cursor.fetchone()[0]

    safe = total - phishing

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        phishing=phishing,
        safe=safe,
        username=session["username"]
    )


# ==================================================
# HISTORY
# ==================================================

@app.route("/history")
@login_required
def history():

    conn = sqlite3.connect(
        "phishing.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],)
    )

    scans = cursor.fetchall()

    conn.close()

    return render_template(
        "history.html",
        scans=scans
    )


# ==================================================
# ANALYTICS
# ==================================================

@app.route("/analytics")
@login_required
def analytics():

    conn = sqlite3.connect(
        "phishing.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ?",
        (session["user_id"],)
    )

    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scans WHERE prediction='PHISHING' AND user_id = ?",
        (session["user_id"],)
    )

    phishing = cursor.fetchone()[0]
    safe = total - phishing

    conn.close()

    return render_template(
        "analytics.html",
        total=total,
        phishing=phishing,
        safe=safe,
        username=session["username"]
    )


# ==================================================
# SCAN EMAIL
# ==================================================

@app.route("/scan", methods=["GET", "POST"])
@login_required
def scan():

    if request.method == "POST":

        # ==================================================
        # 1. GET EMAIL INPUT (TEXT OR FILE)
        # ==================================================

        email_text = ""

        uploaded_file = request.files.get("email_file")

        if uploaded_file and uploaded_file.filename != "":
            filename = uploaded_file.filename.lower()
            content = uploaded_file.read()

            if filename.endswith(".pdf") or content.startswith(b"%PDF"):
                extracted = _extract_text_from_pdf(content)
                if not extracted:
                    return "Unable to extract text from PDF. The file may be image-based or not contain selectable text. Please use a different PDF or submit raw email text."
                email_text = extracted
            else:
                try:
                    email_text = content.decode(
                        "utf-8",
                        errors="ignore"
                    )
                except:
                    return "Invalid file format"

        else:
            email_text = request.form.get("email", "")


        if not email_text.strip():

            return "No email content provided"


        # ==================================================
        # 2. ML PREDICTION
        # ==================================================

        sender_email, receiver_email = _extract_sender_receiver(email_text)
        excerpt = _get_mail_excerpt(email_text, max_chars=240)

        sanitized_text = _sanitize_email_text(email_text)

        if pipeline is not None:
            prediction = pipeline.predict([sanitized_text])[0]
            probability = pipeline.predict_proba([sanitized_text])[0]
        else:
            vector = vectorizer.transform([sanitized_text])
            prediction = model.predict(vector)[0]
            probability = model.predict_proba(vector)[0]

        phishing_prob = float(probability[1])
        safe_prob = float(probability[0])

        confidence = round(max(phishing_prob, safe_prob) * 100, 2)
        model_score = round(phishing_prob * 100)

        result = "PHISHING" if prediction == 1 else "SAFE"
        ai_prediction = None
        ai_confidence = None
        reasons = []

        if AI_ENABLED:
            ai_result = ai_detect_email(email_text)
            if ai_result:
                ai_prediction = ai_result.get("label")
                ai_confidence = round(float(ai_result.get("confidence", 0.0)), 2)
                if ai_prediction == "PHISHING":
                    reasons.append(
                        f"Advanced AI predicted phishing ({ai_confidence}% confidence)"
                    )
                else:
                    reasons.append(
                        f"Advanced AI predicted safe email ({ai_confidence}% confidence)"
                    )

                if ai_prediction == "PHISHING" and result == "SAFE" and ai_confidence >= 85:
                    result = "PHISHING"
                    risk_score = min(100, risk_score + 10)
                elif ai_prediction == "SAFE" and result == "PHISHING" and ai_confidence >= 90:
                    risk_score = max(0, risk_score - 10)


        # ==================================================
        # 2.5 EMAIL HEADER ANALYSIS (SPF, DKIM, DMARC)
        # ==================================================

        try:
            header_analyzer = HeaderAnalyzer()
            header_reasons, header_score = header_analyzer.analyze_headers(email_text)
            reasons.extend(header_reasons)
        except Exception as e:
            reasons.append(f"Note: Email header analysis unavailable ({str(e)[:30]}...)")
            header_score = 0


        # ==================================================
        # 3. RULE-BASED ANALYSIS (EXPLAINABILITY)
        # ==================================================

        extra_score, analyzer_reasons, risk_level = analyze_email(sanitized_text)
        reasons.extend(analyzer_reasons)

        if prediction == 0:
            capped_extra = max(0, min(extra_score, 20))
            risk_score = min(100, model_score + capped_extra)
        else:
            risk_score = min(100, model_score + extra_score)
        
        # Incorporate header analysis score
        if header_score > 30:
            risk_score = min(100, risk_score + (header_score * 0.25))


        # ==================================================
        # 4. RISK LEVEL CLASSIFICATION
        # ==================================================

        if risk_score >= 85:
            risk_level = "HIGH"
        elif risk_score >= 55:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"


        # ==================================================
        # 5. FINAL LABEL
        # ==================================================

        suspicious_clues = [
            r for r in analyzer_reasons
            if any(tok in r.lower() for tok in ["suspicious", "phishing", "urgent", "click", "credentials", "link", "verify", "account"])
        ]

        if risk_score >= 90:
            result = "PHISHING"
        elif prediction == 1 and phishing_prob >= 0.85 and risk_score >= 75:
            result = "PHISHING"
        elif prediction == 1 and phishing_prob >= 0.90 and risk_score >= 70:
            result = "PHISHING"
        elif prediction == 1 and risk_score >= 80:
            result = "PHISHING"
        elif prediction == 1 and phishing_prob < 0.90 and risk_score < 80 and not suspicious_clues:
            result = "SAFE"
        elif safe_prob >= 0.70 and risk_score < 80:
            result = "SAFE"
        else:
            result = "SAFE"


        # Add model-based reason
        _append_model_reasons(reasons, prediction, result, phishing_prob, risk_score)

        # Add the readable final decision reason
        if result == "PHISHING":
            reasons.append(
                f"Final decision: PHISHING because the combined risk score is {risk_score}%, which exceeds the high-risk threshold."
            )
        else:
            reasons.append(
                f"Final decision: SAFE because the combined risk score is {risk_score}%, below the phishing threshold."
            )

        # Normalize, humanize, and remove duplicate reasons while preserving order
        seen = set()
        unique_reasons = []
        for reason in reasons:
            formatted = _humanize_reason_text(reason)
            if formatted not in seen:
                seen.add(formatted)
                unique_reasons.append(formatted)
        reasons = unique_reasons


        # ==================================================
        # 6. SAVE TO DATABASE
        # ==================================================

        conn = sqlite3.connect("phishing.db")
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO scans
        (user_id, email_text, prediction, risk_score, reasons)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            email_text,
            result,
            risk_score,
            " | ".join(reasons)
        ))

        scan_id = cursor.lastrowid

        conn.commit()
        conn.close()


        # ==================================================
        # 7. RETURN RESULT PAGE
        # ==================================================

        return render_template(
            "report.html",
            result=result,
            score=risk_score,
            reasons=reasons,
            risk_level=risk_level,
            confidence=confidence,
            ai_prediction=ai_prediction,
            ai_confidence=ai_confidence,
            ai_enabled=AI_ENABLED,
            scan_id=scan_id,
            sender_email=sender_email,
            receiver_email=receiver_email,
            word_count=len(re.findall(r"\b\w+\b", sanitized_text)),
            excerpt=excerpt,
        )


    # GET REQUEST
    return render_template("scan.html")

# ==================================================
# ADMIN PANEL
# ==================================================

@app.route("/admin")
@login_required
def admin():

    conn = sqlite3.connect(
        "phishing.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users"
    )

    users = cursor.fetchall()

    cursor.execute("""
    SELECT *
    FROM scans
    ORDER BY id DESC
    LIMIT 20
    """)

    scans = cursor.fetchall()

    conn.close()

    return render_template(
        "admin.html",
        users=users,
        scans=scans
    )


# ==================================================
# EXPORT CSV
# ==================================================

@app.route("/export")
@login_required
def export():

    conn = sqlite3.connect(
        "phishing.db"
    )

    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans"
    )

    rows = cursor.fetchall()

    conn.close()

    with open(
        "scan_history.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "ID",
            "USER_ID",
            "EMAIL_TEXT",
            "PREDICTION",
            "RISK_SCORE",
            "REASONS",
            "DATE"
        ])

        writer.writerows(rows)

    return send_file(
        "scan_history.csv",
        as_attachment=True
    )


# ==================================================
# PDF REPORT
# ==================================================

@app.route("/pdf/<int:scan_id>")
@login_required
def pdf(scan_id):

    conn = sqlite3.connect("phishing.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, user_id, email_text, prediction, risk_score, reasons, scan_date
    FROM scans
    WHERE id = ? AND user_id = ?
    """,
    (scan_id, session["user_id"]))

    row = cursor.fetchone()
    conn.close()

    if not row:
        return "Report not found", 404

    email_text = row[2]
    risk_score = row[4]

    vector = vectorizer.transform([email_text])
    probability = model.predict_proba(vector)[0]
    phishing_prob = float(probability[1])
    safe_prob = float(probability[0])
    confidence = round(max(phishing_prob, safe_prob) * 100, 2)

    ai_prediction = None
    ai_confidence = None
    if AI_ENABLED:
        ai_result = ai_detect_email(email_text)
        if ai_result:
            ai_prediction = ai_result.get("label")
            ai_confidence = round(float(ai_result.get("confidence", 0.0)), 2)

    if risk_score >= 80:
        risk_level = "HIGH"
    elif risk_score >= 50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    scan = {
        "id": row[0],
        "email_text": email_text,
        "prediction": row[3],
        "risk_score": risk_score,
        "reasons": row[5],
        "scan_date": row[6],
        "risk_level": risk_level,
    }

    buffer = generate_scan_pdf(
        scan,
        session["username"],
        confidence=confidence,
        phishing_prob=phishing_prob,
        safe_prob=safe_prob,
        ai_prediction=ai_prediction,
        ai_confidence=ai_confidence,
        ai_enabled=AI_ENABLED,
    )

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"phishing_report_{scan_id}.pdf"
    )


# ==================================================
# RUN APP
# ==================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )
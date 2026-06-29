# 🛡️ AI-Powered Phishing Detection & Email Security System

An intelligent Information Security web application that detects phishing emails using Machine Learning, URL reputation analysis, email header inspection, and AI-powered content analysis. The system provides detailed security reports, threat scoring, user authentication, and PDF report generation through a modern web dashboard.

---

## 📌 Features

- 🔐 User Registration & Login Authentication
- 🤖 AI-Based Phishing Email Detection
- 📧 Email Content Analysis
- 🌐 URL Reputation Checking
- 📨 Email Header Analysis
- 📊 Threat Score Calculation
- 📄 Automatic PDF Report Generation
- 📈 Security Analytics Dashboard
- 🗂️ Scan History Management
- 👨‍💼 Admin Dashboard
- 💾 SQLite Database Integration
- 🎨 Responsive Bootstrap User Interface

---

## 🛠️ Technologies Used

### Backend
- Python
- Flask
- SQLite
- Scikit-Learn
- Pandas
- NumPy

### Machine Learning
- Phishing Detection Model
- TF-IDF Vectorizer
- Feature Extraction
- Classification Algorithms

### Frontend
- HTML5
- CSS3
- Bootstrap
- JavaScript
- Jinja2 Templates


## ⚙️ Installation

### 1. Clone Repository

```bash
git clone https://github.com/your-username/info-sec-project.git
cd info-sec-project
```

### 2. Create Virtual Environment

Windows

```bash
python -m venv venv
venv\Scripts\activate
```

Linux / Mac

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Configure Environment Variables

Create a `.env` file and add your configuration values.

Example:

```env
SECRET_KEY=your_secret_key
```

---

### 5. Train the Machine Learning Model (Optional)

```bash
python train_model.py
```

---

### 6. Run the Application

```bash
python app.py
```

The application will start on

```
http://127.0.0.1:5000
```

---

## 🚀 System Workflow

1. User logs into the system.
2. User submits an email for analysis.
3. The application extracts email content.
4. URLs are checked for reputation.
5. Email headers are inspected.
6. Machine Learning model predicts phishing probability.
7. AI combines multiple security indicators.
8. Threat score is calculated.
9. Security report is generated.
10. PDF report can be downloaded.
11. Scan is saved to history.

---

## 🧠 Machine Learning

The phishing detection engine uses:

- Text preprocessing
- Feature extraction
- TF-IDF Vectorization
- Trained Classification Model
- Confidence Scoring

The trained models are stored inside the **models/** directory.

---

## 📊 Dashboard Features

- Scan Statistics
- Threat Analytics
- Detection History
- Security Reports
- Admin Controls
- PDF Downloads

---

## 🔒 Security Features

- Password Authentication
- Session Management
- SQL Injection Protection
- Input Validation
- URL Reputation Verification
- Header Inspection
- AI Threat Scoring

---

## 📄 Reports

The system generates detailed reports including:

- Email Risk Level
- Phishing Probability
- Suspicious URLs
- Header Analysis
- AI Security Assessment
- Threat Score
- PDF Export

---

## 💾 Database

SQLite is used for storing:

- User Accounts
- Login Information
- Scan History
- Detection Results
- Reports

---

## 📸 Screenshots

You can add screenshots here.

```
Login Page

Dashboard

Email Scan

Analytics

Report Generation
```

---

## Future Improvements

- Real-time Email Monitoring
- Gmail API Integration
- Outlook Integration
- VirusTotal API Support
- Deep Learning Detection
- Mobile Application
- Multi-Factor Authentication
- Cloud Deployment
- Docker Support

---

## Requirements

- Python 3.10+
- Flask
- Scikit-Learn
- Pandas
- NumPy
- SQLite

Install using:

```bash
pip install -r requirements.txt
```


# 🛡️ SentinelHive - AI Powered Honeypot Platform

A complete, modular Threat Intelligence Platform with AI-based attack classification, built for a 45-day development cycle.

## 🚀 Architecture
- **Backend**: Python FastAPI (Modular, Async)
- **Database**: Supabase (PostgreSQL + Realtime)
- **AI Engine**: Heuristic Rule-Based Classifier (Regex/Pattern Matching)
- **Frontend**: HTML5, CSS3 (Neon UI), JavaScript (Vanilla)
- **Honeypot**: Custom Python Log Collector (simulated or real)

## 📂 Project Structure
- `ai_engine/`: Attack classification logic and MITRE mapping.
- `backend/`: FastAPI application (API routes, Auth, Models).
- `frontend/`: Web Dashboard and Tools.
- `vm_scripts/`: Python scripts for log collection on the honeypot VM.
- `supabase/`: Database schema and setup SQL.

## 🛠️ Setup Guide

### 1. Prerequisites
- Python 3.9+
- Supabase Account (Free Tier)
- Gmail Account (for SMTP OTP) - *Optional config*

### 2. Database Setup (Supabase)
1. Create a new project in Supabase.
2. Go to the SQL Editor and run the script in `supabase/schema.sql`.
3. Get your `SUPABASE_URL` and `SUPABASE_KEY` from Project Settings.

### 3. Backend Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Create .env file
echo "SUPABASE_URL=your_url" > .env
echo "SUPABASE_KEY=your_key" >> .env
echo "SECRET_KEY=your_jwt_secret" >> .env

# Run Server
uvicorn app.main:app --reload
```

### 4. Frontend Setup
- Open `frontend/index.html` or `frontend/login.html` in your browser.
- Use a Live Server (VS Code Extension) for best experience.
- Ensure `js/api.js` points to `http://localhost:8000/api/v1`.

### 5. AI & Honeypot Setup
- Deploy `vm_scripts/log_collector.py` to your Linux VM.
- Run it to start sending logs to the backend:
```bash
sudo python3 log_collector.py
```

## 🔐 Default Credentials
- **Super Admin**: Register via the signup page, then manually set `role='super_admin'` and `is_approved=TRUE` in Supabase `users` table.

## 📝 Features
- **AI Analysis**: Detects SQLi, XSS, Brute Force.
- **RBAC**: Operative, Specialist, Overseer, Admin roles.
- **Live Feed**: Real-time attack logs.
- **Tools**: URL Analyzer, Hash ID, Secret Finder.
# Phishing Email Detector

A full-stack tool that scores a pasted email for phishing red flags using
rule-based heuristics (no ML yet — that's Phase 4). Built with a React
frontend and a Flask API backend.

## What it checks

- Urgency / pressure language ("act now", "account suspended")
- Requests for sensitive info (passwords, SSNs, bank details)
- Suspicious links: URL shorteners, raw IP links, spoofed brand domains
- Sender display-name vs. actual domain mismatches
- Excessive punctuation, ALL-CAPS words, generic greetings

Each rule that fires adds weighted points to a 0–100 risk score, which maps
to a verdict: **Likely Safe**, **Suspicious**, or **Potential Phishing**.

## Project structure

```
phishing-email-detector/
├── backend/
│   ├── app.py            # Flask API (POST /api/analyze)
│   ├── analyzer.py        # Rule engine / scoring logic
│   ├── test_analyzer.py   # Unit tests for the rule engine
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx        # Main UI: textarea + risk gauge + findings
│   │   ├── App.css
│   │   └── main.jsx
│   ├── index.html
│   ├── package.json
│   └── vite.config.js     # Proxies /api requests to Flask on :5000
└── README.md
```

## Running it locally

You'll need Python 3.9+ and Node.js 18+ installed.

### 1. Backend (Flask API)

```bash
cd backend
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

This starts the API at `http://localhost:5000`. Confirm it's running:

```bash
curl http://localhost:5000/api/health
```

To run the test suite:

```bash
python test_analyzer.py
```

### 2. Frontend (React)

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

This starts the app at `http://localhost:5173`. Vite proxies any `/api/*`
request to the Flask server, so both must be running at the same time.

Open `http://localhost:5173`, paste an email (or click "Load a sample
phishing email"), and click **Analyze Email**.

## API reference

**POST** `/api/analyze`

Request body:
```json
{ "email": "From: ...\nSubject: ...\n\nBody text here" }
```

Response:
```json
{
  "score": 71,
  "verdict": "Potential Phishing",
  "findings": [
    {
      "tag": "SHORTENED LINK",
      "weight": 12,
      "severity": "high",
      "detail": "Link uses a URL shortener (bit.ly), which hides the real destination."
    }
  ]
}
```

## Roadmap (next phases)

- **Phase 4 — Machine learning:** train a classifier (Naive Bayes /
  Logistic Regression) on a Kaggle phishing email dataset with
  pandas + scikit-learn, and add a second `/api/analyze/ml` endpoint
  to compare rule-based vs. ML verdicts.
- **Phase 6 — Deployment:** deploy `frontend/` to Vercel and `backend/`
  to Render (or similar). Set the frontend's API base URL via an
  environment variable instead of the dev-only Vite proxy.

## Disclaimer

This is an educational project. Rule-based heuristics can be wrong in
both directions — always verify unexpected or high-stakes emails through
an official channel before acting on them.

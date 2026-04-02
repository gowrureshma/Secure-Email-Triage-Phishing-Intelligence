# Secure Email Triage & Phishing Intelligence Dashboard

A security-focused application that analyzes incoming emails for phishing indicators, assigns a risk score, and highlights suspicious signals.

## Features

- **Rule-Based Detection**: Analyzes emails for phishing signs using configurable rules
- **Risk Scoring**: Assigns risk scores (0-100) with LOW/MEDIUM/HIGH classifications
- **Explainable AI**: Shows exactly why an email was marked risky with detailed flags
- **Link Analysis**: Checks URLs for suspicious patterns
- **Dashboard**: Visual statistics of email analysis history

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Charts**: Chart.js for visualizations

## Installation

1. Install Python dependencies:
```bash
pip install flask
```

2. Run the application (from the email-triage-dashboard directory):
```bash
cd email-triage-dashboard
python app.py
```

3. Open your browser and navigate to:
```
http://localhost:5000
```

## Troubleshooting

If you see a "Template not found" error, make sure you're running the app from within the `email-triage-dashboard` directory:
```bash
cd email-triage-dashboard
python app.py
```

## Project Structure

```
email-triage-dashboard/
├── app.py                 # Flask backend application
├── detector.py            # Phishing detection engine
├── templates/
│   └── index.html         # Main dashboard HTML
├── static/
│   ├── css/
│   │   └── styles.css     # Dashboard styles
│   └── js/
│       └── app.js         # Frontend JavaScript
└── data/
    └── emails.json        # Email analysis history
```

## Risk Scoring System

| Score Range | Risk Level |
|-------------|------------|
| 0-30        | LOW        |
| 31-60       | MEDIUM     |
| 61-100      | HIGH       |

## Detection Rules

| Rule | Score |
|------|-------|
| Suspicious domain (typosquatting) | +30 |
| Urgent language | +20 |
| Mismatched links | +25 |
| Unknown sender | +15 |
| Suspicious call-to-action | +15 |
| Poor grammar/spelling | +10 |
| Request for sensitive info | +25 |
| Fake login links | +30 |

## API Endpoints

### POST /api/analyze
Analyze an email for phishing indicators.

**Request Body:**
```json
{
  "sender": "sender@example.com",
  "subject": "Email Subject",
  "body": "Email body content",
  "links": ["http://example.com/link"]
}
```

**Response:**
```json
{
  "score": 75,
  "risk": "HIGH",
  "flags": [
    {"type": "urgent_language", "description": "Urgent language detected", "score": 20},
    {"type": "suspicious_domain", "description": "Suspicious domain: paypa1.com", "score": 30}
  ],
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### GET /api/stats
Get dashboard statistics.

**Response:**
```json
{
  "total_analyzed": 100,
  "high_risk": 15,
  "medium_risk": 30,
  "low_risk": 55
}
```

### GET /api/history
Get recent email analysis history.

**Response:**
```json
{
  "emails": [
    {
      "id": 1,
      "sender": "test@example.com",
      "subject": "Test Subject",
      "score": 45,
      "risk": "MEDIUM",
      "timestamp": "2024-01-01T12:00:00Z"
    }
  ]
}
```

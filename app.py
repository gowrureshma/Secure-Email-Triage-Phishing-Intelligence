"""
Flask Backend for Secure Email Triage & Phishing Intelligence Dashboard
API endpoints for email analysis and dashboard statistics
"""

from flask import Flask, request, jsonify, render_template
import json
import os
from datetime import datetime
import re

# Import the phishing detection engine
from detector import PhishingDetector, analyze_email

app = Flask(__name__)

# Get the directory where this script is located
APP_DIR = os.path.dirname(os.path.abspath(__file__))

# File to store email analysis history
DATA_FILE = os.path.join(APP_DIR, 'data', 'emails.json')

# Ensure data directory exists
os.makedirs(os.path.dirname(DATA_FILE), exist_ok=True)

# Initialize data file if it doesn't exist
if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, 'w') as f:
        json.dump({'emails': [], 'total_analyzed': 0}, f)


def load_email_history():
    """Load email analysis history from file"""
    try:
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {'emails': [], 'total_analyzed': 0}


def save_email_history(data):
    """Save email analysis history to file"""
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def extract_links_from_text(text):
    """Extract URLs from email text"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+|www\.[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


@app.route('/')
def index():
    """Serve the main dashboard page"""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze_email_endpoint():
    """
    Analyze an email for phishing indicators
    
    Expected JSON payload:
    {
        "sender": "sender@example.com",
        "subject": "Email Subject",
        "body": "Email body content",
        "links": ["http://example.com/link"] (optional)
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract fields
        sender = data.get('sender', '')
        subject = data.get('subject', '')
        body = data.get('body', '')
        links = data.get('links', [])
        
        # If no links provided, try to extract them from the body
        if not links and body:
            links = extract_links_from_text(body)
        
        # Validate input
        if not body and not subject:
            return jsonify({'error': 'Email body or subject is required'}), 400
        
        # Perform analysis
        detector = PhishingDetector()
        result = detector.analyze(sender, subject, body, links)
        
        # Save to history
        history = load_email_history()
        
        email_record = {
            'id': len(history['emails']) + 1,
            'sender': sender,
            'subject': subject,
            'body_preview': body[:100] + '...' if len(body) > 100 else body,
            'score': result['score'],
            'risk': result['risk'],
            'flags': result['flags'],
            'timestamp': result['timestamp']
        }
        
        history['emails'].insert(0, email_record)  # Add to beginning (most recent first)
        
        # Keep only last 100 emails
        history['emails'] = history['emails'][:100]
        history['total_analyzed'] += 1
        
        save_email_history(history)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    try:
        history = load_email_history()
        
        # Count emails by risk level
        stats = {
            'total_analyzed': history['total_analyzed'],
            'high_risk': 0,
            'medium_risk': 0,
            'low_risk': 0,
            'recent_activity': []
        }
        
        for email in history['emails']:
            if email['risk'] == 'HIGH':
                stats['high_risk'] += 1
            elif email['risk'] == 'MEDIUM':
                stats['medium_risk'] += 1
            else:
                stats['low_risk'] += 1
        
        # Get last 7 days of activity
        stats['recent_activity'] = history['emails'][:7]
        
        return jsonify(stats)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get email analysis history"""
    try:
        limit = request.args.get('limit', 20, type=int)
        history = load_email_history()
        
        return jsonify({
            'emails': history['emails'][:limit],
            'total': len(history['emails'])
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/clear', methods=['POST'])
def clear_history():
    """Clear all email analysis history"""
    try:
        save_email_history({'emails': [], 'total_analyzed': 0})
        return jsonify({'message': 'History cleared successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/demo', methods=['GET'])
def run_demo():
    """Run a demo analysis with sample phishing and legitimate emails"""
    try:
        # Sample phishing email
        phishing_result = analyze_email(
            sender='security@paypa1.com',
            subject='URGENT: Your Account Has Been Compromised!',
            body='''
            Dear Valued Customer,
            
            We have detected unusual activity on your PayPal account. 
            Your account has been LIMITED until you verify your information.
            
            Click here to verify your account: http://192.168.1.1/verify
            
            If you do not verify within 24 hours, your account will be permanently suspended.
            
            Act now to avoid legal action!
            
            Sincerely,
            PayPal Security Team
            ''',
            links=['http://192.168.1.1/verify']
        )
        
        # Sample legitimate email
        legitimate_result = analyze_email(
            sender='newsletter@amazon.com',
            subject='Your Order Has Shipped',
            body='''
            Hello,
            
            Good news! Your order #123-4567890 has shipped and is on its way.
            
            You can track your package in the Amazon app or on our website.
            
            Thank you for shopping with us!
            
            Amazon Customer Service
            ''',
            links=['https://amazon.com/track/123']
        )
        
        return jsonify({
            'phishing_demo': phishing_result,
            'legitimate_demo': legitimate_result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Error handlers
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("=" * 60)
    print("Secure Email Triage & Phishing Intelligence Dashboard")
    print("=" * 60)
    print("\nStarting Flask server...")
    print("Open your browser and navigate to: http://localhost:5000")
    print("\nAPI Endpoints:")
    print("  POST /api/analyze  - Analyze an email for phishing")
    print("  GET  /api/stats    - Get dashboard statistics")
    print("  GET  /api/history - Get email analysis history")
    print("  POST /api/clear   - Clear analysis history")
    print("  GET  /api/demo    - Run demo analysis")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60)
    
    app.run(debug=True, host='0.0.0.0', port=5000)

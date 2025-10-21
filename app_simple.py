from flask import Flask, jsonify, request
from datetime import datetime

app = Flask(__name__)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '')
    
    users = {
        'admin@eduadmin.com': {'name': 'System Admin', 'role': 'admin'},
        'student@eduadmin.com': {'name': 'Alice Student', 'role': 'student'},
        'faculty@eduadmin.com': {'name': 'John Professor', 'role': 'faculty'},
        'staff@eduadmin.com': {'name': 'Robert Staff', 'role': 'staff'}
    }
    
    if email in users:
        return jsonify({
            'access_token': 'simple_token',
            'user': {'email': email, 'role': users[email]['role'], 'name': users[email]['name']}
        })
    else:
        return jsonify({'error': 'Invalid email'}), 401

if __name__ == '__main__':
    print("🚀 SIMPLE BACKEND RUNNING: http://localhost:5000")
    print("🔐 Use: student@eduadmin.com / any-password")
    app.run(host='0.0.0.0', port=5000, debug=False)
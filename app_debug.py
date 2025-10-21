from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime
import traceback

print("🚀 Starting Debug Backend...")

app = Flask(__name__)
app.config['SECRET_KEY'] 'debug-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///debug.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

try:
    db = SQLAlchemy(app)
    CORS(app)
    print("✅ Database initialized")
except Exception as e:
    print(f"❌ Database init failed: {e}")
    traceback.print_exc()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    role = db.Column(db.String(20))

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').lower()
        
        demo_users = {
            'admin@eduadmin.com': {'first_name': 'System', 'last_name': 'Admin', 'role': 'admin'},
            'faculty@eduadmin.com': {'first_name': 'John', 'last_name': 'Professor', 'role': 'faculty'},
            'student@eduadmin.com': {'first_name': 'Alice', 'last_name': 'Student', 'role': 'student'},
            'staff@eduadmin.com': {'first_name': 'Robert', 'last_name': 'Staff', 'role': 'staff'}
        }
        
        if email in demo_users:
            user_data = demo_users[email]
            return jsonify({
                'access_token': 'demo_token',
                'user': {
                    'id': 1,
                    'email': email,
                    'first_name': user_data['first_name'],
                    'last_name': user_data['last_name'],
                    'role': user_data['role']
                }
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        print(f"Login error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'Login failed'}), 500

if __name__ == '__main__':
    try:
        with app.app_context():
            db.create_all()
            print("✅ Database tables created")
        
        print("🚀 BACKEND RUNNING on http://localhost:5000")
        print("🔐 Use any demo email with any password")
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        print(f"❌ Startup failed: {e}")
        traceback.print_exc()
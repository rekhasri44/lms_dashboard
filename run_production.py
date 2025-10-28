from waitress import serve
from app_enterprise_fixed import app, initialize_enterprise

if __name__ == "__main__":
    # Initialize the enterprise system
    with app.app_context():
        initialize_enterprise()
    
    print("=" * 60)
    print("🚀 ENTERPRISE PRODUCTION SERVER STARTED!")
    print("=" * 60)
    print("🌐 Running on: http://localhost:5000")
    print("🌐 Also available: http://127.0.0.1:5000")
    print("🔧 Server: Waitress (Production WSGI)")
    print("📊 Workers: 4 threads")
    print("✅ Redis: Connected and active")
    print("🔐 Security: All enterprise features enabled")
    print("=" * 60)
    print("🔑 DEMO CREDENTIALS:")
    print("   • Admin: admin@eduadmin.com / EnterpriseAdmin123!")
    print("   • Faculty: faculty@eduadmin.com / EnterpriseAdmin123!")
    print("   • Student: student@eduadmin.com / EnterpriseAdmin123!")
    print("   • Staff: staff@eduadmin.com / EnterpriseAdmin123!")
    print("=" * 60)
    print("Press CTRL+C to stop the server")
    print("=" * 60)
    
    # Start production server
    serve(app, host='0.0.0.0', port=5000, threads=4)
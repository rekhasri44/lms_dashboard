from appfinal import db, app
import os

with app.app_context():
    # Drop all tables
    db.drop_all()
    
    # Create all tables with new schema
    db.create_all()
    
    print("✅ Database reset successfully!")
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import enum
import json

db = SQLAlchemy()



class UserRole(enum.Enum):
    ADMIN = "admin"
    FACULTY = "faculty"
    STUDENT = "student"
    STAFF = "staff"

class UserStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"

class StudentStatus(enum.Enum):
    ENROLLED = "enrolled"
    GRADUATED = "graduated"
    DROPPED = "dropped"
    SUSPENDED = "suspended"

class RiskLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class FinancialStatus(enum.Enum):
    PAID = "paid"
    PENDING = "pending"
    OVERDUE = "overdue"

class FacultyPosition(enum.Enum):
    PROFESSOR = "professor"
    ASSOCIATE_PROFESSOR = "associate_professor"
    ASSISTANT_PROFESSOR = "assistant_professor"
    LECTURER = "lecturer"

class FacultyStatus(enum.Enum):
    ACTIVE = "active"
    ON_LEAVE = "on_leave"
    RETIRED = "retired"

class CourseStatus(enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"

class EnrollmentStatus(enum.Enum):
    ENROLLED = "enrolled"
    DROPPED = "dropped"
    COMPLETED = "completed"
    WAITLISTED = "waitlisted"

class AttendanceStatus(enum.Enum):
    PRESENT = "present"
    ABSENT = "absent"
    LATE = "late"
    EXCUSED = "excused"

class TransactionType(enum.Enum):
    TUITION = "tuition"
    FEES = "fees"
    GRANTS = "grants"
    SCHOLARSHIPS = "scholarships"
    EXPENSES = "expenses"

class TransactionCategory(enum.Enum):
    INCOME = "income"
    EXPENSE = "expense"

class AlertType(enum.Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    SUCCESS = "success"

class AlertPriority(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class AnnouncementType(enum.Enum):
    GENERAL = "general"
    ACADEMIC = "academic"
    MAINTENANCE = "maintenance"



class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False)
    status = db.Column(db.Enum(UserStatus), default=UserStatus.ACTIVE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = db.Column(db.DateTime)

class Department(db.Model):
    __tablename__ = 'departments'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(10), nullable=False)
    head_faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.id'))
    budget = db.Column(db.Float, default=0.0)
    student_count = db.Column(db.Integer, default=0)
    faculty_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # foreign_keys for relationships
    head_faculty = db.relationship('Faculty', foreign_keys=[head_faculty_id], backref='headed_departments')

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    enrollment_date = db.Column(db.Date, nullable=False)
    graduation_date = db.Column(db.Date)
    gpa = db.Column(db.Float, default=0.0)
    status = db.Column(db.Enum(StudentStatus), default=StudentStatus.ENROLLED)
    risk_level = db.Column(db.Enum(RiskLevel), default=RiskLevel.LOW)
    financial_status = db.Column(db.Enum(FinancialStatus), default=FinancialStatus.PENDING)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='student_profile')
    department = db.relationship('Department', backref='students')
    enrollments = db.relationship('Enrollment', backref='student')

class Faculty(db.Model):
    __tablename__ = 'faculty'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    hire_date = db.Column(db.Date, nullable=False)
    position = db.Column(db.Enum(FacultyPosition), nullable=False)
    salary = db.Column(db.Float)
    workload_hours = db.Column(db.Integer, default=0)
    research_score = db.Column(db.Float, default=0.0)
    student_satisfaction_score = db.Column(db.Float, default=0.0)
    status = db.Column(db.Enum(FacultyStatus), default=FacultyStatus.ACTIVE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    #  foreign_keys for relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='faculty_profile')
    department = db.relationship('Department', foreign_keys=[department_id], backref='faculty_members')
    course_sections = db.relationship('CourseSection', backref='faculty')

class Course(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    credits = db.Column(db.Integer, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    prerequisites = db.Column(db.Text)
    capacity = db.Column(db.Integer, default=30)
    status = db.Column(db.Enum(CourseStatus), default=CourseStatus.ACTIVE)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    department = db.relationship('Department', backref='courses')
    sections = db.relationship('CourseSection', backref='course')

class CourseSection(db.Model):
    __tablename__ = 'course_sections'
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('courses.id'), nullable=False)
    faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.id'), nullable=False)
    semester = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    section_number = db.Column(db.String(10), nullable=False)
    schedule = db.Column(db.Text)  # JSON: days, times
    room = db.Column(db.String(50))
    capacity = db.Column(db.Integer, default=30)
    enrolled_count = db.Column(db.Integer, default=0)
    waitlist_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Enrollment(db.Model):
    __tablename__ = 'enrollments'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    course_section_id = db.Column(db.Integer, db.ForeignKey('course_sections.id'), nullable=False)
    enrollment_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Enum(EnrollmentStatus), default=EnrollmentStatus.ENROLLED)
    final_grade = db.Column(db.String(5))
    attendance_percentage = db.Column(db.Float, default=100.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Grade(db.Model):
    __tablename__ = 'grades'
    id = db.Column(db.Integer, primary_key=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollments.id'), nullable=False)
    assignment_type = db.Column(db.String(50))
    points_earned = db.Column(db.Float, nullable=False)
    points_possible = db.Column(db.Float, nullable=False)
    grade_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    enrollment_id = db.Column(db.Integer, db.ForeignKey('enrollments.id'), nullable=False)
    class_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Enum(AttendanceStatus), default=AttendanceStatus.PRESENT)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class FinancialTransaction(db.Model):
    __tablename__ = 'financial_transactions'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'))
    transaction_type = db.Column(db.Enum(TransactionType), nullable=False)
    category = db.Column(db.Enum(TransactionCategory), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text)
    transaction_date = db.Column(db.Date, default=datetime.utcnow)
    payment_method = db.Column(db.String(50))
    status = db.Column(db.String(20), default='completed')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class FeeStructure(db.Model):
    __tablename__ = 'fee_structures'
    id = db.Column(db.Integer, primary_key=True)
    academic_year = db.Column(db.String(20), nullable=False)
    semester = db.Column(db.String(20), nullable=False)
    fee_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



class SystemAlert(db.Model):
    __tablename__ = 'system_alerts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    alert_type = db.Column(db.Enum(AlertType), default=AlertType.INFO)
    priority = db.Column(db.Enum(AlertPriority), default=AlertPriority.MEDIUM)
    target_audience = db.Column(db.String(50))
    status = db.Column(db.String(20), default='active')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Announcement(db.Model):
    __tablename__ = 'announcements'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text)
    announcement_type = db.Column(db.Enum(AnnouncementType), default=AnnouncementType.GENERAL)
    target_audience = db.Column(db.String(50), default='all')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    publish_date = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='draft')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SystemMetric(db.Model):
    __tablename__ = 'system_metrics'
    id = db.Column(db.Integer, primary_key=True)
    metric_name = db.Column(db.String(100), nullable=False)
    current_value = db.Column(db.Float, nullable=False)
    threshold_warning = db.Column(db.Float)
    threshold_critical = db.Column(db.Float)
    unit = db.Column(db.String(20))
    status = db.Column(db.String(20), default='normal')
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)


class ComplianceCheck(db.Model):
    __tablename__ = 'compliance_checks'
    id = db.Column(db.Integer, primary_key=True)
    compliance_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    last_check_date = db.Column(db.Date)
    next_check_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    checked_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    parameters = db.Column(db.Text)  # JSON
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    file_path = db.Column(db.String(500))
    status = db.Column(db.String(20), default='generating')
    scheduled = db.Column(db.Boolean, default=False)
    frequency = db.Column(db.String(20))
    next_run = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ReportRecipient(db.Model):
    __tablename__ = 'report_recipients'
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    notification_method = db.Column(db.String(20), default='email')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class StudentIntervention(db.Model):
    __tablename__ = 'student_interventions'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    intervention_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    action_taken = db.Column(db.Text)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'))
    status = db.Column(db.String(20), default='pending')
    priority = db.Column(db.String(20), default='medium')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    student = db.relationship('Student', backref='interventions')
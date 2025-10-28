
## 2. **README.md for Backend** (in `bizvidya_dashboard/`)

```markdown
# EduAdmin Backend API

Enterprise-grade REST API for educational institution management with comprehensive security and analytics.

## 🏗 Architecture

- **Framework:** Flask with SQLAlchemy ORM
- **Authentication:** JWT with refresh tokens
- **Database:** PostgreSQL (Production) / SQLite (Development)
- **Security:** RBAC, Rate Limiting, Input Sanitization
- **Monitoring:** Audit Logging, Performance Metrics

## 🔌 API Endpoints

### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/logout` - User logout  
- `POST /api/v1/auth/refresh` - Token refresh
- `GET /api/v1/auth/me` - Current user profile

### Core Modules
- **Students:** `/api/v1/students/*`
- **Faculty:** `/api/v1/faculty/*` 
- **Courses:** `/api/v1/courses/*`
- **Analytics:** `/api/v1/analytics/*`
- **Reports:** `/api/v1/reports/*`
- **System:** `/api/v1/system/*`

## 🚀 Deployment

```bash
# Production deployment on Render.com
# Auto-deploys from main branch

# Environment Variables Required:
- SECRET_KEY
- JWT_SECRET_KEY  
- DATABASE_URL
- REDIS_URL (optional)
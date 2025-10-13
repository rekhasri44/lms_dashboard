import React, { useState } from 'react';
import { 
  RefreshCw, 
  Save, 
  Database, 
  Mail, 
  Shield, 
  Globe,
  Bell,
  Lock,
  Key,
  FileText,
  Users,
  CheckCircle,
  AlertTriangle,
  Palette
} from 'lucide-react';
import './Settings.css';
import { 
 
  User, 
  BarChart3, 
  BookOpen, 
   
  GraduationCap, 

  Settings,
  Info,
  X,

  Calendar
} from 'lucide-react';
const SettingsPage = () => {
  const [settings, setSettings] = useState({
    institutionName: 'University of Excellence',
    institutionCode: 'UOE-2024',
    timezone: 'UTC-5 (Eastern Time)',
    academicYear: '2023-2024',
    emailNotifications: true,
    smsAlerts: true,
    weeklyReports: true,
    riskAlerts: true,
    twoFactorAuth: true,
    sessionTimeout: true,
    ipRestrictions: false,
    dataEncryption: true,
    auditLogging: true,
    dataRetention: true,
    primaryColor: '#3B82F6',
    logoUrl: 'https://example.com/logo.png',
    darkMode: false,
    compactLayout: false
  });

  const handleToggle = (key) => {
    setSettings(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const handleInputChange = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="settings-page">
          <div className="sidebar">
        <div className="sidebar-header">
          <div className="logo">
            <div className="logo-icon">
              <GraduationCap className="icon-medium" />
            </div>

         
            
          
            <span className="logo-text">EduAdmin</span>
          </div>
        </div>
        
        <nav className="sidebar-nav">
          <div className="nav-section-title">
            Navigation
          </div>
          <div className="nav-links">
            <a href="/" className="nav-link active">
              <BarChart3 className="nav-icon" />
              Overview
            </a>
            <a href="/student" className="nav-link">
              <Users className="nav-icon" />
              Students
            </a>
            <a href="/faculty" className="nav-link">
              <GraduationCap className="nav-icon" />
              Faculty
            </a>
            <a href="/course" className="nav-link">
              <BookOpen className="nav-icon" />
              Courses
            </a>
            <a href="/analytics" className="nav-link">
              <BarChart3 className="nav-icon" />
              Analytics
            </a>
            <a href="/reports" className="nav-link">
              <FileText className="nav-icon" />
              Reports
            </a>
            <a href="/settings" className="nav-link">
              <Settings className="nav-icon" />
              Settings
            </a>
          </div>
        </nav>
      </div>
      <div className='right'>
      <div className="settings-header">
        <div className="settings-header-left">
          <h1 className="settings-page-title">System Settings</h1>
        </div>
        <div className="settings-header-actions">
          <button className="refresh-btn">
            <RefreshCw className="btn-icon" />
            Refresh
          </button>
          <button className="save-changes-btn">
            <Save className="btn-icon" />
            Save Changes
          </button>
        </div>
      </div>

      <div className="settings-content">
        <div className="settings-main">
          {/* System Configuration */}
          <div className="settings-section">
            <div className="section-header">
              <h2 className="section-title">System Configuration</h2>
              <p className="section-subtitle">Manage system settings and preferences</p>
            </div>

            <div className="settings-card">
              <div className="card-header">
                <FileText className="card-icon" />
                <h3 className="card-title">General Settings</h3>
              </div>
              
              <div className="subsection-header">
                <Database className="subsection-icon" />
                <h4 className="subsection-title">Institution Information</h4>
              </div>

              <div className="form-grid">
                <div className="form-group">
                  <label className="form-label">Institution Name</label>
                  <input 
                    type="text" 
                    className="form-input"
                    value={settings.institutionName}
                    onChange={(e) => handleInputChange('institutionName', e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Institution Code</label>
                  <input 
                    type="text" 
                    className="form-input"
                    value={settings.institutionCode}
                    onChange={(e) => handleInputChange('institutionCode', e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Timezone</label>
                  <input 
                    type="text" 
                    className="form-input"
                    value={settings.timezone}
                    onChange={(e) => handleInputChange('timezone', e.target.value)}
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">Academic Year</label>
                  <input 
                    type="text" 
                    className="form-input"
                    value={settings.academicYear}
                    onChange={(e) => handleInputChange('academicYear', e.target.value)}
                  />
                </div>
              </div>

              <div className="subsection-header">
                <Bell className="subsection-icon" />
                <h4 className="subsection-title">Notification Preferences</h4>
              </div>

              <div className="toggle-list">
                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Email Notifications</h5>
                    <p className="toggle-description">Receive system alerts via email</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.emailNotifications}
                      onChange={() => handleToggle('emailNotifications')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">SMS Alerts</h5>
                    <p className="toggle-description">Critical alerts via SMS</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.smsAlerts}
                      onChange={() => handleToggle('smsAlerts')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Weekly Reports</h5>
                    <p className="toggle-description">Automated weekly summary</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.weeklyReports}
                      onChange={() => handleToggle('weeklyReports')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Risk Alerts</h5>
                    <p className="toggle-description">Student at-risk notifications</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.riskAlerts}
                      onChange={() => handleToggle('riskAlerts')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Security Settings */}
          <div className="settings-section">
            <div className="settings-card">
              <div className="subsection-header">
                <Shield className="subsection-icon" />
                <h4 className="subsection-title">Security Settings</h4>
              </div>

              <div className="toggle-list">
                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Two-Factor Authentication</h5>
                    <p className="toggle-description">Require 2FA for admin users</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.twoFactorAuth}
                      onChange={() => handleToggle('twoFactorAuth')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Session Timeout</h5>
                    <p className="toggle-description">Auto-logout after inactivity</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.sessionTimeout}
                      onChange={() => handleToggle('sessionTimeout')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">IP Restrictions</h5>
                    <p className="toggle-description">Restrict access by IP address</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.ipRestrictions}
                      onChange={() => handleToggle('ipRestrictions')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>

              <div className="subsection-header">
                <Lock className="subsection-icon" />
                <h4 className="subsection-title">Data & Privacy</h4>
              </div>

              <div className="toggle-list">
                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Data Encryption</h5>
                    <p className="toggle-description">Encrypt sensitive data at rest</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.dataEncryption}
                      onChange={() => handleToggle('dataEncryption')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Audit Logging</h5>
                    <p className="toggle-description">Log all system activities</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.auditLogging}
                      onChange={() => handleToggle('auditLogging')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>

                <div className="toggle-item">
                  <div className="toggle-info">
                    <h5 className="toggle-title">Data Retention</h5>
                    <p className="toggle-description">Auto-delete old records (7 years)</p>
                  </div>
                  <label className="toggle-switch">
                    <input 
                      type="checkbox" 
                      checked={settings.dataRetention}
                      onChange={() => handleToggle('dataRetention')}
                    />
                    <span className="toggle-slider"></span>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* User Roles & Permissions */}
          <div className="settings-section">
            <div className="settings-card">
              <div className="card-header">
                <Users className="card-icon" />
                <h3 className="card-title">User Roles & Permissions</h3>
              </div>

              <div className="roles-grid">
                <div className="role-card">
                  <div className="role-header">
                    <h4 className="role-name">Administrator</h4>
                    <span className="role-count">3</span>
                  </div>
                  <p className="role-description">Complete system access</p>
                  <div className="role-permissions">
                    <h5 className="permissions-title">PERMISSIONS</h5>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Full Access</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>User Management</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>System Settings</span>
                    </div>
                  </div>
                  <button className="manage-role-btn">Manage Role</button>
                </div>

                <div className="role-card">
                  <div className="role-header">
                    <h4 className="role-name">Faculty</h4>
                    <span className="role-count">324</span>
                  </div>
                  <p className="role-description">Teaching staff access</p>
                  <div className="role-permissions">
                    <h5 className="permissions-title">PERMISSIONS</h5>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Course Management</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Grade Input</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Student Records</span>
                    </div>
                  </div>
                  <button className="manage-role-btn">Manage Role</button>
                </div>

                <div className="role-card">
                  <div className="role-header">
                    <h4 className="role-name">Staff</h4>
                    <span className="role-count">45</span>
                  </div>
                  <p className="role-description">Administrative staff access</p>
                  <div className="role-permissions">
                    <h5 className="permissions-title">PERMISSIONS</h5>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Student Records</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Report Generation</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Data Entry</span>
                    </div>
                  </div>
                  <button className="manage-role-btn">Manage Role</button>
                </div>

                <div className="role-card">
                  <div className="role-header">
                    <h4 className="role-name">Student</h4>
                    <span className="role-count">12,847</span>
                  </div>
                  <p className="role-description">Student portal access</p>
                  <div className="role-permissions">
                    <h5 className="permissions-title">PERMISSIONS</h5>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>View Grades</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Course Registration</span>
                    </div>
                    <div className="permission-item">
                      <CheckCircle className="permission-icon" />
                      <span>Profile Management</span>
                    </div>
                  </div>
                  <button className="manage-role-btn">Manage Role</button>
                </div>
              </div>
            </div>
          </div>

          {/* Appearance & Branding */}
          <div className="settings-section">
            <div className="settings-card">
              <div className="card-header">
                <Palette className="card-icon" />
                <h3 className="card-title">Appearance & Branding</h3>
              </div>

              <div className="appearance-grid">
                <div className="appearance-left">
                  <div className="form-group">
                    <label className="form-label">Primary Color</label>
                    <div className="color-input-wrapper">
                      <input 
                        type="text" 
                        className="form-input"
                        value={settings.primaryColor}
                        onChange={(e) => handleInputChange('primaryColor', e.target.value)}
                      />
                      <div 
                        className="color-preview" 
                        style={{ backgroundColor: settings.primaryColor }}
                      ></div>
                    </div>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Institution Logo URL</label>
                    <input 
                      type="text" 
                      className="form-input"
                      value={settings.logoUrl}
                      onChange={(e) => handleInputChange('logoUrl', e.target.value)}
                    />
                  </div>
                </div>

                <div className="appearance-right">
                  <div className="toggle-item">
                    <div className="toggle-info">
                      <h5 className="toggle-title">Dark Mode</h5>
                      <p className="toggle-description">Enable dark theme</p>
                    </div>
                    <label className="toggle-switch">
                      <input 
                        type="checkbox" 
                        checked={settings.darkMode}
                        onChange={() => handleToggle('darkMode')}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>

                  <div className="toggle-item">
                    <div className="toggle-info">
                      <h5 className="toggle-title">Compact Layout</h5>
                      <p className="toggle-description">Reduce spacing for more content</p>
                    </div>
                    <label className="toggle-switch">
                      <input 
                        type="checkbox" 
                        checked={settings.compactLayout}
                        onChange={() => handleToggle('compactLayout')}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* System Status Sidebar */}
        <div className="settings-sidebar">
          <div className="status-card">
            <div className="status-header">
              <Database className="status-icon" />
              <h3 className="status-title">System Status</h3>
            </div>

            <div className="status-list">
              <div className="status-item">
                <div className="status-item-icon">
                  <Database className="icon-sm" />
                </div>
                <div className="status-item-content">
                  <h4 className="status-item-title">Database Connection</h4>
                  <p className="status-item-time">2 minutes ago</p>
                </div>
                <span className="status-badge healthy">healthy</span>
              </div>

              <div className="status-item">
                <div className="status-item-icon">
                  <Mail className="icon-sm" />
                </div>
                <div className="status-item-content">
                  <h4 className="status-item-title">Email Service</h4>
                  <p className="status-item-time">5 minutes ago</p>
                </div>
                <span className="status-badge healthy">healthy</span>
              </div>

              <div className="status-item">
                <div className="status-item-icon">
                  <Shield className="icon-sm" />
                </div>
                <div className="status-item-content">
                  <h4 className="status-item-title">Backup System</h4>
                  <p className="status-item-time">1 hour ago</p>
                </div>
                <span className="status-badge warning">warning</span>
              </div>

              <div className="status-item">
                <div className="status-item-icon">
                  <Globe className="icon-sm" />
                </div>
                <div className="status-item-content">
                  <h4 className="status-item-title">API Gateway</h4>
                  <p className="status-item-time">1 minute ago</p>
                </div>
                <span className="status-badge healthy">healthy</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      </div>
    </div>
  );
};

export default SettingsPage;
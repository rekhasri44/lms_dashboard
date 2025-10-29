
const SECURITY_CONSTANTS = {
  MAX_ATTEMPTS: 5,
  LOCK_DURATION: 15 * 60 * 1000, // 15 minutes
  ATTEMPT_WINDOW: 30 * 60 * 1000 // 30 minutes
};

export const securityService = {
  recordFailedAttempt(attempts) {
    const now = Date.now();
    
    if (attempts >= SECURITY_CONSTANTS.MAX_ATTEMPTS) {
      const lockTime = now + SECURITY_CONSTANTS.LOCK_DURATION;
      localStorage.setItem('login_lock', lockTime.toString());
      localStorage.setItem('login_attempts', '0');
      localStorage.setItem('lock_reason', 'max_attempts_reached');
      return lockTime;
    }
    
    localStorage.setItem('login_attempts', attempts.toString());
    localStorage.setItem('last_attempt', now.toString());
    return null;
  },

  checkRateLimit() {
    const lockTime = localStorage.getItem('login_lock');
    
    if (lockTime) {
      const now = Date.now();
      const lockUntil = parseInt(lockTime);
      
      if (now < lockUntil) {
        return lockUntil;
      } else {
        this.clearLock();
      }
    }
    
    // Clear old attempts outside the window
    const lastAttempt = localStorage.getItem('last_attempt');
    if (lastAttempt) {
      const timeSinceLastAttempt = Date.now() - parseInt(lastAttempt);
      if (timeSinceLastAttempt > SECURITY_CONSTANTS.ATTEMPT_WINDOW) {
        this.resetAttempts();
      }
    }
    
    return null;
  },

  resetAttempts() {
    localStorage.removeItem('login_attempts');
    localStorage.removeItem('last_attempt');
    localStorage.removeItem('login_lock');
    localStorage.removeItem('lock_reason');
  },

  clearLock() {
    localStorage.removeItem('login_lock');
    localStorage.removeItem('lock_reason');
  },

  getRemainingAttempts() {
    const attempts = parseInt(localStorage.getItem('login_attempts') || '0');
    return Math.max(0, SECURITY_CONSTANTS.MAX_ATTEMPTS - attempts);
  },

  getSecurityStatus() {
    const lockTime = this.checkRateLimit();
    const attempts = parseInt(localStorage.getItem('login_attempts') || '0');
    const lastAttempt = localStorage.getItem('last_attempt');
    
    return {
      isLocked: !!lockTime,
      lockUntil: lockTime,
      failedAttempts: attempts,
      lastAttempt: lastAttempt ? new Date(parseInt(lastAttempt)) : null,
      remainingAttempts: this.getRemainingAttempts()
    };
  }
};
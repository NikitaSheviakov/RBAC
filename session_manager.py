"""
Session Manager for RBAC System
Handles session management, active role control, and session constraints
"""
import json
import time
from datetime import datetime, timedelta
from database import get_db_connection
from audit import log_event
from constraint_manager import ConstraintManager

class SessionManager:
    """
    Manages user sessions, active roles, and session lifecycle
    """
    
    def __init__(self):
        self.constraint_manager = ConstraintManager()
    
    def get_session_info(self, session_id):
        """
        Get complete session information
        Returns session data including user info and roles
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT s.id, s.user_id, s.active_roles, s.login_time, s.last_activity,
                   u.username, 
                   (SELECT GROUP_CONCAT(r.name) 
                    FROM user_roles ur 
                    JOIN roles r ON ur.role_id = r.id 
                    WHERE ur.user_id = s.user_id) as assigned_roles
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.id = ? AND s.is_active = 1
        """, (session_id,))
        
        session = cursor.fetchone()
        conn.close()
        
        if session:
            return {
                'session_id': session['id'],
                'user_id': session['user_id'],
                'username': session['username'],
                'active_roles': json.loads(session['active_roles']),
                'assigned_roles': session['assigned_roles'].split(',') if session['assigned_roles'] else [],
                'login_time': session['login_time'],
                'last_activity': session['last_activity']
            }
        
        return None
    
    def update_active_roles(self, session_id, new_active_roles):
        """
        Update active roles for a session with constraint checking
        Returns success status and message
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get session info
            cursor.execute("SELECT user_id, active_roles FROM sessions WHERE id = ?", (session_id,))
            session = cursor.fetchone()
            
            if not session:
                conn.close()
                return False, "Session not found"
            
            user_id = session['user_id']
            
            # Validate that new active roles are subset of assigned roles
            cursor.execute("""
                SELECT r.name 
                FROM roles r
                JOIN user_roles ur ON r.id = ur.role_id
                WHERE ur.user_id = ?
            """, (user_id,))
            
            assigned_roles = [row['name'] for row in cursor.fetchall()]
            
            # Check if all new active roles are assigned to user
            for role in new_active_roles:
                if role not in assigned_roles:
                    conn.close()
                    return False, f"Role '{role}' is not assigned to user"
            
            # Check dynamic constraints
            constraint_error = self.constraint_manager.check_dynamic_constraint(user_id, new_active_roles)
            if constraint_error:
                conn.close()
                return False, constraint_error
            
            # Update active roles and last activity
            cursor.execute("""
                UPDATE sessions 
                SET active_roles = ?, last_activity = CURRENT_TIMESTAMP 
                WHERE id = ?
            """, (json.dumps(new_active_roles), session_id))
            
            conn.commit()
            conn.close()
            
            log_event(user_id, "role_activation", 
                     details=f"Active roles updated to: {new_active_roles}", 
                     success=True)
            
            return True, f"Active roles updated successfully: {', '.join(new_active_roles)}"
            
        except Exception as e:
            conn.close()
            log_event(session['user_id'] if session else None, "role_activation", 
                     details=f"Failed to update active roles: {e}", success=False)
            return False, f"Error updating active roles: {e}"
    
    def activate_single_role(self, session_id, role_name):
        """
        Activate a single role (deactivate others)
        Useful for role switching during session
        """
        session_info = self.get_session_info(session_id)
        if not session_info:
            return False, "Session not found"
        
        if role_name not in session_info['assigned_roles']:
            return False, f"Role '{role_name}' is not assigned to user"
        
        # Check dynamic constraints with single role (usually no constraint issues)
        constraint_error = self.constraint_manager.check_dynamic_constraint(
            session_info['user_id'], [role_name]
        )
        if constraint_error:
            return False, constraint_error
        
        return self.update_active_roles(session_id, [role_name])
    
    def add_role_to_active(self, session_id, role_name):
        """
        Add a role to currently active roles
        """
        session_info = self.get_session_info(session_id)
        if not session_info:
            return False, "Session not found"
        
        if role_name not in session_info['assigned_roles']:
            return False, f"Role '{role_name}' is not assigned to user"
        
        if role_name in session_info['active_roles']:
            return False, f"Role '{role_name}' is already active"
        
        new_active_roles = session_info['active_roles'] + [role_name]
        
        return self.update_active_roles(session_id, new_active_roles)
    
    def remove_role_from_active(self, session_id, role_name):
        """
        Remove a role from currently active roles
        """
        session_info = self.get_session_info(session_id)
        if not session_info:
            return False, "Session not found"
        
        if role_name not in session_info['active_roles']:
            return False, f"Role '{role_name}' is not active"
        
        new_active_roles = [r for r in session_info['active_roles'] if r != role_name]
        
        # Ensure at least one role remains active
        if not new_active_roles:
            return False, "Cannot remove all active roles. At least one role must remain active."
        
        return self.update_active_roles(session_id, new_active_roles)
    
    def refresh_session(self, session_id):
        """
        Update last_activity timestamp to keep session alive
        Returns True if session is still valid, False if expired
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if session exists and is not expired
        cursor.execute("""
            SELECT user_id, login_time, last_activity 
            FROM sessions 
            WHERE id = ? AND is_active = 1
        """, (session_id,))
        
        session = cursor.fetchone()
        if not session:
            conn.close()
            return False
        
        # Check session expiration (8 hours)
        last_activity = datetime.fromisoformat(session['last_activity'])
        if datetime.now() - last_activity > timedelta(hours=8):
            # Session expired
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session_id,))
            conn.commit()
            conn.close()
            
            log_event(session['user_id'], "session_expired", 
                     details="Session expired due to inactivity", success=True)
            return False
        
        # Update last activity
        cursor.execute("""
            UPDATE sessions 
            SET last_activity = CURRENT_TIMESTAMP 
            WHERE id = ?
        """, (session_id,))
        
        conn.commit()
        conn.close()
        return True
    
    def end_session(self, session_id):
        """
        End a user session
        Returns True on success, False on failure
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get user ID from session for logging
            cursor.execute("SELECT user_id FROM sessions WHERE id = ?", (session_id,))
            session = cursor.fetchone()
            
            if session:
                user_id = session['user_id']
                
                # End session
                cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session_id,))
                conn.commit()
                conn.close()
                
                log_event(user_id, "session_end", details="Session ended by user", success=True)
                return True
            else:
                conn.close()
                return False
                
        except Exception as e:
            print(f"Session end error: {e}")
            conn.close()
            return False
    
    def get_user_sessions(self, user_id):
        """
        Get all active sessions for a user
        Returns list of session information
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, active_roles, login_time, last_activity 
            FROM sessions 
            WHERE user_id = ? AND is_active = 1
            ORDER BY login_time DESC
        """, (user_id,))
        
        sessions = []
        for row in cursor.fetchall():
            sessions.append({
                'session_id': row['id'],
                'active_roles': json.loads(row['active_roles']),
                'login_time': row['login_time'],
                'last_activity': row['last_activity']
            })
        
        conn.close()
        return sessions
    
    def cleanup_expired_sessions(self):
        """
        Clean up expired sessions (inactive for more than 8 hours)
        Returns number of sessions cleaned up
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Find expired sessions
        cursor.execute("""
            SELECT id, user_id, last_activity 
            FROM sessions 
            WHERE is_active = 1 
            AND datetime(last_activity) < datetime('now', '-8 hours')
        """)
        
        expired_sessions = cursor.fetchall()
        
        # Deactivate expired sessions
        for session in expired_sessions:
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE id = ?", (session['id'],))
            log_event(session['user_id'], "session_expired", 
                     details="Session expired and cleaned up", success=True)
        
        conn.commit()
        conn.close()
        
        return len(expired_sessions)
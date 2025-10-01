"""
Authentication module for RBAC System
Handles user registration, login, and session management
"""
import hashlib
import json
from database import get_db_connection
from audit import log_event

def register_user(username, password):
    """
    Register a new user in the system
    Returns user ID on success, None on failure
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username already exists
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print("Error: Username already exists")
        conn.close()
        return None
    
    # Hash password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        cursor.execute("""
            INSERT INTO users (username, password_hash) 
            VALUES (?, ?)
        """, (username, password_hash))
        
        user_id = cursor.lastrowid
        
        # Assign default 'user' role to new users
        cursor.execute("SELECT id FROM roles WHERE name = 'user'")
        user_role = cursor.fetchone()
        
        if user_role:
            cursor.execute("""
                INSERT INTO user_roles (user_id, role_id) 
                VALUES (?, ?)
            """, (user_id, user_role[0]))
        
        conn.commit()
        conn.close()
        
        log_event(user_id, "user_register", details=f"User {username} registered", success=True)
        print(f"User {username} registered successfully with 'user' role")
        return user_id
        
    except Exception as e:
        print(f"Registration error: {e}")
        conn.close()
        log_event(None, "user_register", details=f"Failed to register {username}: {e}", success=False)
        return None

def login_user(username, password):
    """
    Authenticate user and create session
    Returns session data on success, None on failure
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Find user by username
    cursor.execute("""
        SELECT id, username, password_hash, is_active 
        FROM users 
        WHERE username = ?
    """, (username,))
    
    user = cursor.fetchone()
    
    if not user:
        print("Error: User not found")
        conn.close()
        log_event(None, "user_login", details=f"User {username} not found", success=False)
        return None
    
    if not user['is_active']:
        print("Error: User account is deactivated")
        conn.close()
        log_event(user['id'], "user_login", details="Account deactivated", success=False)
        return None
    
    # Verify password
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user['password_hash'] == password_hash:
        # Get user's assigned roles
        cursor.execute("""
            SELECT r.name 
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = ?
        """, (user['id'],))
        
        assigned_roles = [row['name'] for row in cursor.fetchall()]
        
        # For first login, activate all assigned roles by default
        active_roles = assigned_roles  # Start with all assigned roles active
        
        # Create session
        cursor.execute("""
            INSERT INTO sessions (user_id, active_roles) 
            VALUES (?, ?)
        """, (user['id'], json.dumps(active_roles)))
        
        session_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        user_data = {
            'user_id': user['id'],
            'username': user['username'],
            'session_id': session_id,
            'assigned_roles': assigned_roles,
            'active_roles': active_roles
        }
        
        log_event(user['id'], "user_login", details=f"Session started with roles: {active_roles}", success=True)
        print(f"Login successful. Active roles: {', '.join(active_roles)}")
        return user_data
    else:
        print("Error: Invalid password")
        conn.close()
        log_event(user['id'], "user_login", details="Invalid password", success=False)
        return None

def logout_user(session_id):
    """
    End user session
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
            
            log_event(user_id, "user_logout", details="Session ended", success=True)
            print("Logout successful")
            return True
        else:
            conn.close()
            return False
            
    except Exception as e:
        print(f"Logout error: {e}")
        conn.close()
        return False

def get_user_roles(user_id):
    """
    Get all roles assigned to a user
    Returns list of role names
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT r.name 
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
    """, (user_id,))
    
    roles = [row['name'] for row in cursor.fetchall()]
    conn.close()
    
    return roles

def get_active_roles(session_id):
    """
    Get currently active roles for a session
    Returns list of active role names
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT active_roles FROM sessions WHERE id = ? AND is_active = 1", (session_id,))
    session = cursor.fetchone()
    conn.close()

def update_active_roles(session_id, new_active_roles):
    """
    Update active roles for a session with constraint checking
    Returns success status and message
    """
    from constraint_manager import ConstraintManager
    
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
        
        # Check dynamic constraints
        cm = ConstraintManager()
        constraint_error = cm.check_dynamic_constraint(user_id, new_active_roles)
        if constraint_error:
            conn.close()
            return False, constraint_error
        
        # Update active roles
        cursor.execute("""
            UPDATE sessions SET active_roles = ? 
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

def get_session_info(session_id):
    """
    Get complete session information
    Returns session data including user info and roles
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.id, s.user_id, s.active_roles, s.login_time, s.last_activity,
               u.username, ur.assigned_roles
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        LEFT JOIN (
            SELECT ur.user_id, GROUP_CONCAT(r.name) as assigned_roles
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            GROUP BY ur.user_id
        ) ur ON s.user_id = ur.user_id
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
    
    if session and session['active_roles']:
        return json.loads(session['active_roles'])
    else:
        return []
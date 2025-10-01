"""
Database management for RBAC System
Handles SQLite database initialization and connection
"""
import sqlite3
import json
import hashlib
from config import DATABASE_NAME, ROLES, ROLE_PERMISSIONS

def get_db_connection():
    """Create and return database connection"""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """
    Initialize database with required tables for RBAC system
    Creates tables for users, roles, permissions, sessions, and audit
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create roles table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    """)
    
    # Create user_roles table (many-to-many relationship)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, role_id),
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
        )
    """)
    
    # Create permissions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT
        )
    """)
    
    # Create role_permissions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
        )
    """)
    
    # Create objects table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS objects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            content TEXT,
            owner_id INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    """)
    
    # Create sessions table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            active_roles TEXT,  -- JSON array of active role names
            login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # Create constraints table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS role_constraints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            constraint_type TEXT NOT NULL,  -- 'static' or 'dynamic'
            role1_id INTEGER NOT NULL,
            role2_id INTEGER NOT NULL,
            description TEXT,
            FOREIGN KEY (role1_id) REFERENCES roles (id),
            FOREIGN KEY (role2_id) REFERENCES roles (id)
        )
    """)
    
    # Create audit logs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            role_name TEXT,
            object_id INTEGER,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            success BOOLEAN,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (object_id) REFERENCES objects (id)
        )
    """)
    
    # Insert default roles
    for role_name, description in ROLES.items():
        cursor.execute("""
            INSERT OR IGNORE INTO roles (name, description) 
            VALUES (?, ?)
        """, (role_name, description))
    
    # Insert permissions
    from config import PERMISSIONS
    for perm_name, description in PERMISSIONS.items():
        cursor.execute("""
            INSERT OR IGNORE INTO permissions (name, description) 
            VALUES (?, ?)
        """, (perm_name, description))
    
    # Assign permissions to roles
    for role_name, permissions in ROLE_PERMISSIONS.items():
        # Get role ID
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
        role_result = cursor.fetchone()
        
        if role_result:
            role_id = role_result[0]
            
            for perm_name in permissions:
                # Get permission ID
                cursor.execute("SELECT id FROM permissions WHERE name = ?", (perm_name,))
                perm_result = cursor.fetchone()
                
                if perm_result:
                    perm_id = perm_result[0]
                    cursor.execute("""
                        INSERT OR IGNORE INTO role_permissions (role_id, permission_id) 
                        VALUES (?, ?)
                    """, (role_id, perm_id))
    
    # Insert static constraints
    from config import STATIC_CONSTRAINTS
    for role1, role2 in STATIC_CONSTRAINTS:
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role1,))
        role1_result = cursor.fetchone()
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role2,))
        role2_result = cursor.fetchone()
        
        if role1_result and role2_result:
            cursor.execute("""
                INSERT OR IGNORE INTO role_constraints (constraint_type, role1_id, role2_id, description)
                VALUES ('static', ?, ?, 'Static constraint between roles')
            """, (role1_result[0], role2_result[0]))
    
    # Insert dynamic constraints  
    from config import DYNAMIC_CONSTRAINTS
    for role1, role2 in DYNAMIC_CONSTRAINTS:
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role1,))
        role1_result = cursor.fetchone()
        cursor.execute("SELECT id FROM roles WHERE name = ?", (role2,))
        role2_result = cursor.fetchone()
        
        if role1_result and role2_result:
            cursor.execute("""
                INSERT OR IGNORE INTO role_constraints (constraint_type, role1_id, role2_id, description)
                VALUES ('dynamic', ?, ?, 'Dynamic constraint between roles')
            """, (role1_result[0], role2_result[0]))
    
    # Create default admin user
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    
    if user_count == 0:
        admin_password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO users (username, password_hash) 
            VALUES (?, ?)
        """, ('admin', admin_password_hash))
        
        # Assign admin role to admin user
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        admin_user_id = cursor.fetchone()[0]
        
        cursor.execute("SELECT id FROM roles WHERE name = 'admin'")
        admin_role_id = cursor.fetchone()[0]
        
        cursor.execute("""
            INSERT INTO user_roles (user_id, role_id) 
            VALUES (?, ?)
        """, (admin_user_id, admin_role_id))
        
        print("Default admin user created: admin / admin123")
    
    conn.commit()
    conn.close()
    print("RBAC Database initialized successfully")

def get_db():
    """Return database connection for use in other modules"""
    return get_db_connection()
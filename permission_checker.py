"""
Permission Checker for RBAC System
Handles permission verification and access control checks
"""
import json
from database import get_db_connection
from audit import log_event

class PermissionChecker:
    """
    Verifies user permissions and handles access control decisions
    """
    
    def __init__(self):
        pass
    
    def check_permission(self, user_id, permission, object_id=None):
        """
        Check if user has specific permission through active roles
        Returns True if permitted, False otherwise
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get user's active roles from session
            cursor.execute("""
                SELECT active_roles FROM sessions 
                WHERE user_id = ? AND is_active = 1
            """, (user_id,))
            
            session = cursor.fetchone()
            if not session:
                conn.close()
                log_event(user_id, "permission_check", object_id, 
                         f"No active session for permission: {permission}", False)
                return False
            
            active_roles = json.loads(session['active_roles'])
            
            # Check each active role for the permission
            for role_name in active_roles:
                cursor.execute("""
                    SELECT 1 
                    FROM permissions p
                    JOIN role_permissions rp ON p.id = rp.permission_id
                    JOIN roles r ON r.id = rp.role_id
                    WHERE r.name = ? AND p.name = ?
                """, (role_name, permission))
                
                if cursor.fetchone():
                    conn.close()
                    log_event(user_id, "permission_check", object_id, 
                             f"Permission granted: {permission} via role: {role_name}", True)
                    return True
            
            # Permission denied
            conn.close()
            log_event(user_id, "permission_check", object_id, 
                     f"Permission denied: {permission}. Active roles: {active_roles}", False)
            return False
            
        except Exception as e:
            conn.close()
            log_event(user_id, "permission_check", object_id, 
                     f"Error checking permission: {e}", False)
            return False
    
    def get_user_permissions(self, user_id):
        """
        Get all permissions available to user through active roles
        Returns list of permission names
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user's active roles from session
        cursor.execute("""
            SELECT active_roles FROM sessions 
            WHERE user_id = ? AND is_active = 1
        """, (user_id,))
        
        session = cursor.fetchone()
        if not session:
            conn.close()
            return []
        
        active_roles = json.loads(session['active_roles'])
        
        # Get all permissions from active roles
        permissions = set()
        for role_name in active_roles:
            cursor.execute("""
                SELECT p.name 
                FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                JOIN roles r ON r.id = rp.role_id
                WHERE r.name = ?
            """, (role_name,))
            
            for row in cursor.fetchall():
                permissions.add(row['name'])
        
        conn.close()
        return list(permissions)
    
    def can_access_object(self, user_id, object_id, action):
        """
        Check if user can perform specific action on object
        Handles object ownership and permissions
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get object info
            cursor.execute("SELECT owner_id FROM objects WHERE id = ?", (object_id,))
            object_info = cursor.fetchone()
            
            if not object_info:
                conn.close()
                return False
            
            owner_id = object_info['owner_id']
            
            # Object owner has full access to their objects
            if user_id == owner_id:
                conn.close()
                log_event(user_id, f"object_{action}", object_id, 
                         "Access granted: object owner", True)
                return True
            
            # Check specific permission for the action
            permission_map = {
                'read': 'read_object',
                'write': 'write_object', 
                'delete': 'delete_object'
            }
            
            required_permission = permission_map.get(action)
            if required_permission and self.check_permission(user_id, required_permission, object_id):
                conn.close()
                return True
            
            conn.close()
            return False
            
        except Exception as e:
            conn.close()
            log_event(user_id, f"object_{action}", object_id, 
                     f"Error checking object access: {e}", False)
            return False
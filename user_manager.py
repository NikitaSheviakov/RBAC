"""
User Manager for RBAC System
Handles user management operations with admin privileges
"""
from database import get_db_connection
from audit import log_event
from config import ROLES

class UserManager:
    """
    User management system with administrative functions
    Requires appropriate privilege levels for operations
    """
    
    def __init__(self):
        pass
    
    def list_all_users(self, requester_id):
        """
        List all users in the system
        Only accessible to users with 'list_users' permission
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, is_active, created_at 
            FROM users 
            ORDER BY id ASC
        """)
        
        users = cursor.fetchall()
        conn.close()
        
        formatted_users = []
        for user in users:
            # Get user's roles
            roles = self._get_user_roles(user['id'])
            
            # Check if user has any admin roles
            has_admin_role = any(role in ['admin', 'security_officer'] for role in roles)
            
            formatted_users.append({
                'id': user['id'],
                'username': user['username'],
                'roles': ', '.join(roles) if roles else 'No roles',
                'is_active': bool(user['is_active']),
                'is_super_admin': has_admin_role,
                'created_at': user['created_at']
            })
        
        log_event(requester_id, "list_users", details=f"Listed {len(formatted_users)} users", success=True)
        return formatted_users, None
    
    def get_user_info(self, requester_id, target_user_id=None):
        """
        Get user information
        Users can view their own info, admins can view any user's info
        """
        if target_user_id is None:
            target_user_id = requester_id  # View own profile
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, username, is_active, created_at 
            FROM users WHERE id = ?
        """, (target_user_id,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return None, "User not found"
        
        # Get user roles
        roles = self._get_user_roles(target_user_id)
        
        user_info = {
            'id': user['id'],
            'username': user['username'],
            'roles': ', '.join(roles) if roles else 'No roles assigned',
            'is_active': bool(user['is_active']),
            'is_super_admin': any(role in ['admin', 'security_officer'] for role in roles),
            'created_at': user['created_at']
        }
        
        log_event(requester_id, "view_user_info", 
                 details=f"Viewed info for user ID: {target_user_id}", success=True)
        return user_info, None
    
    def deactivate_user(self, requester_id, target_user_id):
        """
        Deactivate a user account
        Only accessible to users with 'deactivate_user' permission
        """
        from permission_checker import PermissionChecker
        checker = PermissionChecker()
        if not checker.check_permission(requester_id, 'deactivate_user'):
            return False, "Insufficient permissions to deactivate users"
        
        target_username = self._get_username(target_user_id)
        if not target_username:
            return False, "Target user not found"
        
        # Cannot deactivate yourself
        if requester_id == target_user_id:
            return False, "Cannot deactivate your own account"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("UPDATE users SET is_active = 0 WHERE id = ?", (target_user_id,))
            conn.commit()
            log_event(requester_id, "deactivate_user", 
                     details=f"Deactivated user: {target_username}", success=True)
            conn.close()
            return True, f"User {target_username} deactivated successfully"
        except Exception as e:
            log_event(requester_id, "deactivate_user", 
                     details=f"Failed to deactivate {target_username}: {e}", success=False)
            conn.close()
            return False, f"Error deactivating user: {e}"
    
    def activate_user(self, requester_id, target_user_id):
        """
        Activate a deactivated user account
        Only accessible to users with 'deactivate_user' permission (same as activate)
        """
        from permission_checker import PermissionChecker
        checker = PermissionChecker()
        if not checker.check_permission(requester_id, 'deactivate_user'):
            return False, "Insufficient permissions to activate users"
        
        target_username = self._get_username(target_user_id)
        if not target_username:
            return False, "Target user not found"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("UPDATE users SET is_active = 1 WHERE id = ?", (target_user_id,))
            conn.commit()
            log_event(requester_id, "activate_user", 
                     details=f"Activated user: {target_username}", success=True)
            conn.close()
            return True, f"User {target_username} activated successfully"
        except Exception as e:
            log_event(requester_id, "activate_user", 
                     details=f"Failed to activate {target_username}: {e}", success=False)
            conn.close()
            return False, f"Error activating user: {e}"
    
    def _get_user_roles(self, user_id):
        """Get roles for a user"""
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
    
    def _get_username(self, user_id):
        """Get username by user ID"""
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        return user['username'] if user else None

    def get_system_statistics(self, requester_id):
        """
        Get system statistics (user counts, object counts by level)
        Only accessible to users with 'view_statistics' permission
        """
        from permission_checker import PermissionChecker
        checker = PermissionChecker()
        if not checker.check_permission(requester_id, 'view_statistics'):
            return None, "Insufficient permissions to view statistics"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # User statistics
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
        active_users = cursor.fetchone()[0]
        
        # Role statistics
        cursor.execute("SELECT COUNT(*) FROM roles")
        total_roles = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT user_id) FROM user_roles")
        users_with_roles = cursor.fetchone()[0]
        
        # Object statistics
        cursor.execute("SELECT COUNT(*) FROM objects")
        total_objects = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(DISTINCT owner_id) FROM objects")
        users_with_objects = cursor.fetchone()[0]
        
        conn.close()
        
        statistics = {
            'users': {
                'total': total_users,
                'active': active_users,
                'with_roles': users_with_roles
            },
            'roles': {
                'total': total_roles
            },
            'objects': {
                'total': total_objects,
                'users_with_objects': users_with_objects
            }
        }
        
        log_event(requester_id, "view_statistics", details="Viewed system statistics", success=True)
        return statistics, None
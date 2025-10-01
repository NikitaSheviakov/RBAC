"""
Role Manager for RBAC System
Handles role assignments, permissions, and role management
"""
import json
from database import get_db_connection
from audit import log_event

class RoleManager:
    """
    Manages role assignments, permissions, and role operations
    """
    
    def __init__(self):
        pass
    
    def assign_role_to_user(self, requester_id, target_user_id, role_name):
        """
        Assign a role to a user (requires appropriate permissions)
        Returns success status and message
        """
        # Check if requester has permission to assign roles
        if not self._check_permission(requester_id, 'assign_roles'):
            return False, "Insufficient permissions to assign roles"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Check if target user exists
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (target_user_id,))
            target_user = cursor.fetchone()
            if not target_user:
                conn.close()
                return False, "Target user not found"
            
            # Check if role exists
            cursor.execute("SELECT id, name FROM roles WHERE name = ?", (role_name,))
            role = cursor.fetchone()
            if not role:
                conn.close()
                return False, f"Role '{role_name}' not found"
            
            # Check static constraints
            constraint_violation = self._check_static_constraints(target_user_id, role['id'])
            if constraint_violation:
                conn.close()
                return False, f"Static constraint violation: {constraint_violation}"
            
            # Check if role is already assigned
            cursor.execute("""
                SELECT 1 FROM user_roles 
                WHERE user_id = ? AND role_id = ?
            """, (target_user_id, role['id']))
            
            if cursor.fetchone():
                conn.close()
                return False, f"User already has role '{role_name}'"
            
            # Assign role
            cursor.execute("""
                INSERT INTO user_roles (user_id, role_id) 
                VALUES (?, ?)
            """, (target_user_id, role['id']))
            
            conn.commit()
            conn.close()
            
            # Log the assignment
            log_event(
                requester_id, "role_assignment", 
                role_name=role_name,
                details=f"Assigned role '{role_name}' to user '{target_user['username']}'",
                success=True
            )
            
            return True, f"Role '{role_name}' assigned to user '{target_user['username']}' successfully"
            
        except Exception as e:
            conn.close()
            log_event(requester_id, "role_assignment", 
                     details=f"Failed to assign role: {e}", success=False)
            return False, f"Error assigning role: {e}"
    
    def remove_role_from_user(self, requester_id, target_user_id, role_name):
        """
        Remove a role from a user (requires appropriate permissions)
        Returns success status and message
        """
        # Check if requester has permission to assign roles (same as remove)
        if not self._check_permission(requester_id, 'assign_roles'):
            return False, "Insufficient permissions to remove roles"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Check if target user exists
            cursor.execute("SELECT id, username FROM users WHERE id = ?", (target_user_id,))
            target_user = cursor.fetchone()
            if not target_user:
                conn.close()
                return False, "Target user not found"
            
            # Check if role exists
            cursor.execute("SELECT id, name FROM roles WHERE name = ?", (role_name,))
            role = cursor.fetchone()
            if not role:
                conn.close()
                return False, f"Role '{role_name}' not found"
            
            # Check if role is assigned
            cursor.execute("""
                SELECT 1 FROM user_roles 
                WHERE user_id = ? AND role_id = ?
            """, (target_user_id, role['id']))
            
            if not cursor.fetchone():
                conn.close()
                return False, f"User does not have role '{role_name}'"
            
            # Remove role
            cursor.execute("""
                DELETE FROM user_roles 
                WHERE user_id = ? AND role_id = ?
            """, (target_user_id, role['id']))
            
            # Also deactivate this role in any active sessions
            cursor.execute("""
                SELECT id, active_roles FROM sessions 
                WHERE user_id = ? AND is_active = 1
            """, (target_user_id,))
            
            active_sessions = cursor.fetchall()
            for session in active_sessions:
                active_roles = json.loads(session['active_roles'])
                if role_name in active_roles:
                    active_roles.remove(role_name)
                    cursor.execute("""
                        UPDATE sessions SET active_roles = ? 
                        WHERE id = ?
                    """, (json.dumps(active_roles), session['id']))
            
            conn.commit()
            conn.close()
            
            # Log the removal
            log_event(
                requester_id, "role_removal", 
                role_name=role_name,
                details=f"Removed role '{role_name}' from user '{target_user['username']}'",
                success=True
            )
            
            return True, f"Role '{role_name}' removed from user '{target_user['username']}' successfully"
            
        except Exception as e:
            conn.close()
            log_event(requester_id, "role_removal", 
                     details=f"Failed to remove role: {e}", success=False)
            return False, f"Error removing role: {e}"
    
    def get_user_roles(self, user_id):
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
    
    def get_role_permissions(self, role_name):
        """
        Get all permissions for a specific role
        Returns list of permission names
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT p.name 
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            JOIN roles r ON r.id = rp.role_id
            WHERE r.name = ?
        """, (role_name,))
        
        permissions = [row['name'] for row in cursor.fetchall()]
        conn.close()
        
        return permissions
    
    def get_all_roles(self):
        """
        Get all available roles in the system
        Returns list of role information
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT r.name, r.description, 
                   GROUP_CONCAT(p.name, ', ') as permissions
            FROM roles r
            LEFT JOIN role_permissions rp ON r.id = rp.role_id
            LEFT JOIN permissions p ON p.id = rp.permission_id
            GROUP BY r.id, r.name, r.description
        """)
        
        roles = []
        for row in cursor.fetchall():
            roles.append({
                'name': row['name'],
                'description': row['description'],
                'permissions': row['permissions'].split(', ') if row['permissions'] else []
            })
        
        conn.close()
        return roles
    
    def _check_permission(self, user_id, permission):
        """
        Check if user has specific permission through any active role
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
                return True
        
        conn.close()
        return False
    
    def _check_static_constraints(self, user_id, new_role_id):
        """
        Check if assigning new role would violate static constraints
        Returns constraint message if violation, None otherwise
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user's current roles
        cursor.execute("""
            SELECT role_id FROM user_roles WHERE user_id = ?
        """, (user_id,))
        
        current_role_ids = [row['role_id'] for row in cursor.fetchall()]
        
        # Check constraints
        cursor.execute("""
            SELECT rc.constraint_type, r1.name as role1, r2.name as role2
            FROM role_constraints rc
            JOIN roles r1 ON rc.role1_id = r1.id
            JOIN roles r2 ON rc.role2_id = r2.id
            WHERE rc.constraint_type = 'static'
            AND ((rc.role1_id = ? AND rc.role2_id IN ({})) 
              OR (rc.role2_id = ? AND rc.role1_id IN ({})))
        """.format(','.join('?' * len(current_role_ids)), 
                  ','.join('?' * len(current_role_ids))),
        [new_role_id] + current_role_ids + [new_role_id] + current_role_ids)
        
        constraint = cursor.fetchone()
        conn.close()
        
        if constraint:
            return f"Cannot have both '{constraint['role1']}' and '{constraint['role2']}' roles"
        
        return None
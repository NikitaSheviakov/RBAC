"""
Constraint Manager for RBAC System
Handles static and dynamic role constraints
"""
from database import get_db_connection
from audit import log_event

class ConstraintManager:
    """
    Manages role constraints and validates role assignments/activations
    """
    
    def __init__(self):
        pass
    
    def check_static_constraint(self, user_id, new_role_name):
        """
        Check if assigning new role would violate static constraints
        Returns error message if violation, None otherwise
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get new role ID
        cursor.execute("SELECT id FROM roles WHERE name = ?", (new_role_name,))
        new_role = cursor.fetchone()
        if not new_role:
            conn.close()
            return f"Role '{new_role_name}' not found"
        
        new_role_id = new_role['id']
        
        # Get user's current role IDs
        cursor.execute("""
            SELECT role_id FROM user_roles WHERE user_id = ?
        """, (user_id,))
        
        current_role_ids = [row['role_id'] for row in cursor.fetchall()]
        
        # Check static constraints
        cursor.execute("""
            SELECT r1.name as role1, r2.name as role2, rc.description
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
            return f"Static constraint violation: Cannot have both '{constraint['role1']}' and '{constraint['role2']}' roles"
        
        return None
    
    def check_dynamic_constraint(self, user_id, active_roles):
        """
        Check if current active roles violate dynamic constraints
        Returns error message if violation, None otherwise
        """
        if len(active_roles) < 2:
            return None  # No constraint possible with less than 2 roles
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Convert role names to IDs for checking
        role_ids = []
        for role_name in active_roles:
            cursor.execute("SELECT id FROM roles WHERE name = ?", (role_name,))
            role = cursor.fetchone()
            if role:
                role_ids.append(role['id'])
        
        # Check all combinations of active roles for dynamic constraints
        for i in range(len(role_ids)):
            for j in range(i + 1, len(role_ids)):
                cursor.execute("""
                    SELECT r1.name as role1, r2.name as role2, rc.description
                    FROM role_constraints rc
                    JOIN roles r1 ON rc.role1_id = r1.id
                    JOIN roles r2 ON rc.role2_id = r2.id
                    WHERE rc.constraint_type = 'dynamic'
                    AND ((rc.role1_id = ? AND rc.role2_id = ?)
                      OR (rc.role1_id = ? AND rc.role2_id = ?))
                """, (role_ids[i], role_ids[j], role_ids[j], role_ids[i]))
                
                constraint = cursor.fetchone()
                if constraint:
                    conn.close()
                    return f"Dynamic constraint violation: Cannot activate both '{constraint['role1']}' and '{constraint['role2']}' in same session"
        
        conn.close()
        return None
    
    def add_static_constraint(self, requester_id, role1_name, role2_name, description=""):
        """
        Add a new static constraint between two roles
        Requires manage_roles permission
        """
        # Check permission
        from role_manager import RoleManager
        rm = RoleManager()
        if not rm._check_permission(requester_id, 'manage_roles'):
            return False, "Insufficient permissions to manage constraints"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get role IDs
            cursor.execute("SELECT id FROM roles WHERE name = ?", (role1_name,))
            role1 = cursor.fetchone()
            cursor.execute("SELECT id FROM roles WHERE name = ?", (role2_name,))
            role2 = cursor.fetchone()
            
            if not role1 or not role2:
                conn.close()
                return False, "One or both roles not found"
            
            # Check if constraint already exists
            cursor.execute("""
                SELECT 1 FROM role_constraints 
                WHERE constraint_type = 'static'
                AND ((role1_id = ? AND role2_id = ?) 
                  OR (role1_id = ? AND role2_id = ?))
            """, (role1['id'], role2['id'], role2['id'], role1['id']))
            
            if cursor.fetchone():
                conn.close()
                return False, f"Static constraint between '{role1_name}' and '{role2_name}' already exists"
            
            # Add constraint
            cursor.execute("""
                INSERT INTO role_constraints (constraint_type, role1_id, role2_id, description)
                VALUES ('static', ?, ?, ?)
            """, (role1['id'], role2['id'], description))
            
            conn.commit()
            conn.close()
            
            log_event(requester_id, "constraint_add", 
                     details=f"Added static constraint between {role1_name} and {role2_name}", 
                     success=True)
            
            return True, f"Static constraint between '{role1_name}' and '{role2_name}' added successfully"
            
        except Exception as e:
            conn.close()
            log_event(requester_id, "constraint_add", 
                     details=f"Failed to add constraint: {e}", success=False)
            return False, f"Error adding constraint: {e}"
    
    def get_all_constraints(self):
        """
        Get all constraints in the system
        Returns list of constraint information
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT rc.constraint_type, r1.name as role1, r2.name as role2, rc.description
            FROM role_constraints rc
            JOIN roles r1 ON rc.role1_id = r1.id
            JOIN roles r2 ON rc.role2_id = r2.id
            ORDER BY rc.constraint_type, r1.name, r2.name
        """)
        
        constraints = []
        for row in cursor.fetchall():
            constraints.append({
                'type': row['constraint_type'],
                'role1': row['role1'],
                'role2': row['role2'],
                'description': row['description']
            })
        
        conn.close()
        return constraints
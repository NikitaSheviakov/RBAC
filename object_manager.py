"""
Object Manager for RBAC System
Handles object operations with RBAC permission checks
"""
from database import get_db_connection
from audit import log_event
from permission_checker import PermissionChecker

class ObjectManager:
    """
    Manages objects (files) with RBAC permission enforcement
    """
    
    def __init__(self):
        self.permission_checker = PermissionChecker()
    
    def create_object(self, user_id, name, content):
        """
        Create a new object
        Returns success status and object ID
        """
        # Check create_object permission
        if not self.permission_checker.check_permission(user_id, 'create_object'):
            return False, "Insufficient permissions to create objects"
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Check if object name already exists
            cursor.execute("SELECT id FROM objects WHERE name = ?", (name,))
            if cursor.fetchone():
                conn.close()
                return False, f"Object with name '{name}' already exists"
            
            # Create object
            cursor.execute("""
                INSERT INTO objects (name, content, owner_id) 
                VALUES (?, ?, ?)
            """, (name, content, user_id))
            
            object_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            log_event(user_id, "object_create", object_id, 
                     f"Object '{name}' created successfully", True)
            
            return True, object_id
            
        except Exception as e:
            conn.close()
            log_event(user_id, "object_create", None, 
                     f"Failed to create object '{name}': {e}", False)
            return False, f"Error creating object: {e}"
    
    def read_object(self, user_id, object_id):
        """
        Read object content
        Returns object data if permitted, None if denied
        """
        # First check read permission
        if not self.permission_checker.check_permission(user_id, 'read_object'):
            log_event(user_id, "object_read", object_id, 
                     "Read permission denied", False)
            return None
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT o.id, o.name, o.content, o.owner_id, o.created_at, u.username as owner_name
                FROM objects o
                JOIN users u ON o.owner_id = u.id
                WHERE o.id = ?
            """, (object_id,))
            
            obj = cursor.fetchone()
            conn.close()
            
            if not obj:
                log_event(user_id, "object_read", object_id, 
                         "Object not found", False)
                return None
            
            # Object found and user has read permission
            log_event(user_id, "object_read", object_id, 
                     f"Read object '{obj['name']}'", True)
            
            return {
                'id': obj['id'],
                'name': obj['name'],
                'content': obj['content'],
                'owner_id': obj['owner_id'],
                'owner_name': obj['owner_name'],
                'created_at': obj['created_at']
            }
            
        except Exception as e:
            conn.close()
            log_event(user_id, "object_read", object_id, 
                     f"Error reading object: {e}", False)
            return None
    
    def update_object(self, user_id, object_id, new_content):
        """
        Update object content
        Returns success status and message
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get object info
            cursor.execute("SELECT name, owner_id FROM objects WHERE id = ?", (object_id,))
            obj = cursor.fetchone()
            
            if not obj:
                conn.close()
                return False, "Object not found"
            
            object_name = obj['name']
            owner_id = obj['owner_id']
            
            # Check if user is owner or has write_object permission
            if user_id == owner_id:
                # Owner can always update their objects
                pass
            elif not self.permission_checker.check_permission(user_id, 'write_object'):
                conn.close()
                log_event(user_id, "object_update", object_id, 
                         "Write permission denied", False)
                return False, "Insufficient permissions to update object"
            
            # Update object
            cursor.execute("""
                UPDATE objects 
                SET content = ? 
                WHERE id = ?
            """, (new_content, object_id))
            
            conn.commit()
            conn.close()
            
            log_event(user_id, "object_update", object_id, 
                     f"Object '{object_name}' updated successfully", True)
            
            return True, f"Object '{object_name}' updated successfully"
            
        except Exception as e:
            conn.close()
            log_event(user_id, "object_update", object_id, 
                     f"Failed to update object: {e}", False)
            return False, f"Error updating object: {e}"
    
    def delete_object(self, user_id, object_id):
        """
        Delete an object
        Returns success status and message
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            # Get object info
            cursor.execute("SELECT name, owner_id FROM objects WHERE id = ?", (object_id,))
            obj = cursor.fetchone()
            
            if not obj:
                conn.close()
                return False, "Object not found"
            
            object_name = obj['name']
            owner_id = obj['owner_id']
            
            # Check if user is owner or has delete_object permission
            if user_id == owner_id:
                # Owner can always delete their objects
                pass
            elif not self.permission_checker.check_permission(user_id, 'delete_object'):
                conn.close()
                log_event(user_id, "object_delete", object_id, 
                         "Delete permission denied", False)
                return False, "Insufficient permissions to delete object"
            
            # Delete object
            cursor.execute("DELETE FROM objects WHERE id = ?", (object_id,))
            
            conn.commit()
            conn.close()
            
            log_event(user_id, "object_delete", object_id, 
                     f"Object '{object_name}' deleted successfully", True)
            
            return True, f"Object '{object_name}' deleted successfully"
            
        except Exception as e:
            conn.close()
            log_event(user_id, "object_delete", object_id, 
                     f"Failed to delete object: {e}", False)
            return False, f"Error deleting object: {e}"
    
    def list_objects(self, user_id, filter_owner=None):
        """
        List objects accessible to user
        Returns list of object information
        """
        # Check read_object permission
        if not self.permission_checker.check_permission(user_id, 'read_object'):
            log_event(user_id, "object_list", None, 
                     "List objects permission denied", False)
            return []
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            query = """
                SELECT o.id, o.name, o.owner_id, o.created_at, u.username as owner_name
                FROM objects o
                JOIN users u ON o.owner_id = u.id
                WHERE 1=1
            """
            params = []
            
            # Filter by owner if specified
            if filter_owner:
                query += " AND o.owner_id = ?"
                params.append(filter_owner)
            
            query += " ORDER BY o.created_at DESC"
            
            cursor.execute(query, params)
            objects = []
            
            for row in cursor.fetchall():
                objects.append({
                    'id': row['id'],
                    'name': row['name'],
                    'owner_id': row['owner_id'],
                    'owner_name': row['owner_name'],
                    'created_at': row['created_at']
                })
            
            conn.close()
            
            log_event(user_id, "object_list", None, 
                     f"Listed {len(objects)} objects", True)
            
            return objects
            
        except Exception as e:
            conn.close()
            log_event(user_id, "object_list", None, 
                     f"Error listing objects: {e}", False)
            return []
    
    def search_objects(self, user_id, search_term):
        """
        Search objects by name
        Returns matching objects
        """
        # Check read_object permission
        if not self.permission_checker.check_permission(user_id, 'read_object'):
            return []
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT o.id, o.name, o.owner_id, o.created_at, u.username as owner_name
                FROM objects o
                JOIN users u ON o.owner_id = u.id
                WHERE o.name LIKE ?
                ORDER BY o.name
            """, (f"%{search_term}%",))
            
            objects = []
            for row in cursor.fetchall():
                objects.append({
                    'id': row['id'],
                    'name': row['name'],
                    'owner_id': row['owner_id'],
                    'owner_name': row['owner_name'],
                    'created_at': row['created_at']
                })
            
            conn.close()
            
            log_event(user_id, "object_search", None, 
                     f"Searched for '{search_term}', found {len(objects)} objects", True)
            
            return objects
            
        except Exception as e:
            conn.close()
            log_event(user_id, "object_search", None, 
                     f"Error searching objects: {e}", False)
            return []
    
    def get_object_info(self, user_id, object_id):
        """
        Get object metadata without content
        Useful for displaying object information
        """
        # Check read_object permission
        if not self.permission_checker.check_permission(user_id, 'read_object'):
            return None
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                SELECT o.id, o.name, o.owner_id, o.created_at, u.username as owner_name
                FROM objects o
                JOIN users u ON o.owner_id = u.id
                WHERE o.id = ?
            """, (object_id,))
            
            obj = cursor.fetchone()
            conn.close()
            
            if obj:
                return {
                    'id': obj['id'],
                    'name': obj['name'],
                    'owner_id': obj['owner_id'],
                    'owner_name': obj['owner_name'],
                    'created_at': obj['created_at']
                }
            
            return None
            
        except Exception as e:
            conn.close()
            return None
    
    def get_user_objects(self, user_id):
        """
        Get objects owned by specific user
        Returns list of objects
        """
        return self.list_objects(user_id, filter_owner=user_id)
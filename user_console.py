"""
User Console for RBAC System
Provides user interface for object operations and role management
"""
from tabulate import tabulate
from object_manager import ObjectManager
from session_manager import SessionManager
from permission_checker import PermissionChecker
from role_manager import RoleManager
from audit import get_audit_logs

class UserConsole:
    """
    User interface for RBAC system operations
    Provides object management and role control capabilities
    """
    
    def __init__(self):
        self.object_manager = ObjectManager()
        self.session_manager = SessionManager()
        self.permission_checker = PermissionChecker()
        self.role_manager = RoleManager()
    
    def display_user_menu(self, username, active_roles):
        """Display user menu options based on active roles"""
        role_display = ", ".join(active_roles) if active_roles else "No active roles"
        
        menu = f"""
RBAC USER CONSOLE - Welcome {username}
Active Roles: {role_display}

OBJECT OPERATIONS:
  create_obj    - Create new object
  list_obj      - List accessible objects
  read_obj      - Read object content
  write_obj     - Update object content  
  delete_obj     - Delete object
  search_obj    - Search objects by name
  my_objects    - List my objects

ROLE MANAGEMENT:
  my_roles      - Show my assigned and active roles
  activate_role - Activate specific role
  switch_roles  - Change active roles
  add_role      - Add role to active set
  remove_role   - Remove role from active set

SESSION MANAGEMENT:
  session_info  - Show current session information
  refresh       - Refresh session

AUDIT & INFO:
  my_permissions - Show my current permissions
  view_my_audit - View my audit history
  whoami        - Show my user information

SYSTEM:
  admin         - Enter administrative console (if permitted)
  help          - Show this menu
  logout        - Logout and exit system
"""
        print(menu)
    
    def handle_create_object(self, user_id):
        """Handle object creation"""
        name = input("Enter object name: ").strip()
        content = input("Enter object content: ").strip()
        
        success, result = self.object_manager.create_object(user_id, name, content)
        if success:
            print(f"Object created successfully with ID: {result}")
        else:
            print(f"Error: {result}")
    
    def handle_list_objects(self, user_id):
        """List accessible objects"""
        objects = self.object_manager.list_objects(user_id)
        
        if not objects:
            print("No objects found")
            return
        
        table_data = []
        for obj in objects:
            table_data.append([
                obj['id'],
                obj['name'],
                obj['owner_name'],
                obj['created_at'][:16]
            ])
        
        headers = ["ID", "Name", "Owner", "Created"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal objects: {len(objects)}")
    
    def handle_read_object(self, user_id):
        """Read object content"""
        try:
            object_id = int(input("Enter object ID: ").strip())
        except ValueError:
            print("Error: Please enter a valid object ID")
            return
        
        obj_data = self.object_manager.read_object(user_id, object_id)
        if obj_data:
            print(f"\nObject: {obj_data['name']} (Owner: {obj_data['owner_name']})")
            print(f"Created: {obj_data['created_at']}")
            print(f"Content: {obj_data['content']}")
        else:
            print("Object not found or access denied")
    
    def handle_write_object(self, user_id):
        """Update object content"""
        try:
            object_id = int(input("Enter object ID: ").strip())
            new_content = input("Enter new content: ").strip()
        except ValueError:
            print("Error: Please enter a valid object ID")
            return
        
        success, message = self.object_manager.update_object(user_id, object_id, new_content)
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_delete_object(self, user_id):
        """Delete object"""
        try:
            object_id = int(input("Enter object ID to delete: ").strip())
        except ValueError:
            print("Error: Please enter a valid object ID")
            return
        
        confirm = input("Are you sure you want to delete this object? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("Deletion cancelled")
            return
        
        success, message = self.object_manager.delete_object(user_id, object_id)
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_search_objects(self, user_id):
        """Search objects by name"""
        search_term = input("Enter search term: ").strip()
        objects = self.object_manager.search_objects(user_id, search_term)
        
        if not objects:
            print("No matching objects found")
            return
        
        table_data = []
        for obj in objects:
            table_data.append([
                obj['id'],
                obj['name'],
                obj['owner_name'],
                obj['created_at'][:16]
            ])
        
        headers = ["ID", "Name", "Owner", "Created"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nFound {len(objects)} matching objects")
    
    def handle_my_objects(self, user_id):
        """List objects owned by current user"""
        objects = self.object_manager.get_user_objects(user_id)
        
        if not objects:
            print("You don't have any objects")
            return
        
        table_data = []
        for obj in objects:
            table_data.append([
                obj['id'],
                obj['name'],
                obj['created_at'][:16]
            ])
        
        headers = ["ID", "Name", "Created"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nYour objects: {len(objects)}")
    
    def handle_my_roles(self, session_id):
        """Show user's assigned and active roles"""
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found")
            return
        
        print(f"\nUser: {session_info['username']}")
        print(f"Assigned Roles: {', '.join(session_info['assigned_roles']) if session_info['assigned_roles'] else 'None'}")
        print(f"Active Roles: {', '.join(session_info['active_roles']) if session_info['active_roles'] else 'None'}")
        
        # Show permissions for active roles
        permissions = self.permission_checker.get_user_permissions(session_info['user_id'])
        print(f"Current Permissions: {', '.join(permissions) if permissions else 'None'}")
    
    def handle_activate_role(self, session_id):
        """Activate a single role (deactivate others)"""
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found")
            return
        
        print("Your assigned roles:")
        for role in session_info['assigned_roles']:
            print(f"  - {role}")
        
        role_name = input("\nEnter role name to activate: ").strip()
        
        success, message = self.session_manager.activate_single_role(session_id, role_name)
        if success:
            print(f"Success: {message}")
            
            # Show new permissions
            new_permissions = self.permission_checker.get_user_permissions(session_info['user_id'])
            print(f"New permissions: {', '.join(new_permissions) if new_permissions else 'None'}")
        else:
            print(f"Error: {message}")
    
    def handle_switch_roles(self, session_id):
        """Change active roles"""
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found")
            return
        
        print("Your assigned roles:")
        for i, role in enumerate(session_info['assigned_roles'], 1):
            active_indicator = " ✓" if role in session_info['active_roles'] else ""
            print(f"  {i}. {role}{active_indicator}")
        
        print("\nEnter role numbers to activate (comma-separated, e.g., '1,3'):")
        try:
            choices = input("Roles: ").strip().split(',')
            selected_roles = []
            
            for choice in choices:
                role_index = int(choice.strip()) - 1
                if 0 <= role_index < len(session_info['assigned_roles']):
                    selected_roles.append(session_info['assigned_roles'][role_index])
            
            if not selected_roles:
                print("No valid roles selected")
                return
            
            success, message = self.session_manager.update_active_roles(session_id, selected_roles)
            if success:
                print(f"Success: {message}")
            else:
                print(f"Error: {message}")
                
        except ValueError:
            print("Error: Please enter valid role numbers")
    
    def handle_add_role(self, session_id):
        """Add role to active set"""
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found")
            return
        
        available_roles = [r for r in session_info['assigned_roles'] if r not in session_info['active_roles']]
        
        if not available_roles:
            print("No additional roles available to activate")
            return
        
        print("Available roles to add:")
        for role in available_roles:
            print(f"  - {role}")
        
        role_name = input("\nEnter role name to add: ").strip()
        
        success, message = self.session_manager.add_role_to_active(session_id, role_name)
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_remove_role(self, session_id):
        """Remove role from active set"""
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found")
            return
        
        if not session_info['active_roles']:
            print("No active roles to remove")
            return
        
        print("Currently active roles:")
        for role in session_info['active_roles']:
            print(f"  - {role}")
        
        role_name = input("\nEnter role name to remove: ").strip()
        
        success, message = self.session_manager.remove_role_from_active(session_id, role_name)
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_session_info(self, session_id):
        """Show current session information"""
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found")
            return
        
        print("\nCURRENT SESSION INFORMATION:")
        print("=" * 40)
        print(f"User: {session_info['username']}")
        print(f"Session ID: {session_info['session_id']}")
        print(f"Active Roles: {', '.join(session_info['active_roles']) if session_info['active_roles'] else 'None'}")
        print(f"Login Time: {session_info['login_time']}")
        print(f"Last Activity: {session_info['last_activity']}")
        
        # Check session validity
        if self.session_manager.refresh_session(session_id):
            print("Session Status: Active and valid")
        else:
            print("Session Status: Expired or invalid")
    
    def handle_my_permissions(self, user_id):
        """Show user's current permissions"""
        permissions = self.permission_checker.get_user_permissions(user_id)
        
        if not permissions:
            print("You don't have any active permissions")
            return
        
        print("\nYOUR CURRENT PERMISSIONS:")
        for permission in sorted(permissions):
            print(f"  - {permission}")
        
        print(f"\nTotal permissions: {len(permissions)}")
    
    def handle_view_my_audit(self, user_id):
        """View user's audit history"""
        logs = get_audit_logs(limit=20, filters={'user_id': user_id})
        
        if not logs:
            print("No audit records found for your account")
            return
        
        table_data = []
        for log in logs:
            table_data.append([
                log['timestamp'][:16],
                log['event_type'],
                log['object_name'] or '',
                log['details'][:40] + '...' if len(log['details']) > 40 else log['details'],
                "SUCCESS" if log['success'] else "FAILED"
            ])
        
        headers = ["Timestamp", "Event", "Object", "Details", "Result"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nShowing your {len(logs)} most recent activities")
    
    def handle_whoami(self, user_id, session_id):
        """Show comprehensive user information"""
        from user_manager import UserManager
        user_mgr = UserManager()
        
        user_info, error = user_mgr.get_user_info(user_id)
        if error:
            print(f"Error: {error}")
            return
        
        session_info = self.session_manager.get_session_info(session_id)
        
        print("\nYOUR PROFILE INFORMATION:")
        print("=" * 50)
        for key, value in user_info.items():
            formatted_key = key.replace('_', ' ').title()
            print(f"{formatted_key}: {value}")
        
        if session_info:
            print(f"\nSession Active Roles: {', '.join(session_info['active_roles']) if session_info['active_roles'] else 'None'}")
        
        permissions = self.permission_checker.get_user_permissions(user_id)
        print(f"Current Permissions: {len(permissions)} available")
    
    def run_user_console(self, user_data):
        """Run user console interface"""
        user_id = user_data['user_id']
        username = user_data['username']
        session_id = user_data['session_id']
        active_roles = user_data['active_roles']
        
        print("\n" + "=" * 60)
        print(f"          RBAC SYSTEM - USER CONSOLE")
        print("=" * 60)
        self.display_user_menu(username, active_roles)
        
        while True:
            try:
                # Create prompt with username and active roles
                role_display = "/".join(active_roles) if active_roles else "no-roles"
                prompt = f"{username}({role_display})> "
                command = input(prompt).strip().lower()
                
                if command == "":
                    continue
                elif command == "help":
                    self.display_user_menu(username, active_roles)
                elif command == "logout":
                    from auth import logout_user
                    logout_user(session_id)
                    print("Logged out successfully. Goodbye!")
                    return True  # Signal to exit system
                
                # Object Operations
                elif command == "create_obj":
                    self.handle_create_object(user_id)
                elif command == "list_obj":
                    self.handle_list_objects(user_id)
                elif command == "read_obj":
                    self.handle_read_object(user_id)
                elif command == "write_obj":
                    self.handle_write_object(user_id)
                elif command == "delete_obj":
                    self.handle_delete_object(user_id)
                elif command == "search_obj":
                    self.handle_search_objects(user_id)
                elif command == "my_objects":
                    self.handle_my_objects(user_id)
                
                # Role Management
                elif command == "my_roles":
                    self.handle_my_roles(session_id)
                elif command == "activate_role":
                    self.handle_activate_role(session_id)
                elif command == "switch_roles":
                    self.handle_switch_roles(session_id)
                elif command == "add_role":
                    self.handle_add_role(session_id)
                elif command == "remove_role":
                    self.handle_remove_role(session_id)
                
                # Session Management
                elif command == "session_info":
                    self.handle_session_info(session_id)
                elif command == "refresh":
                    if self.session_manager.refresh_session(session_id):
                        print("Session refreshed successfully")
                    else:
                        print("Session refresh failed - session may be expired")
                
                # Audit & Info
                elif command == "my_permissions":
                    self.handle_my_permissions(user_id)
                elif command == "view_my_audit":
                    self.handle_view_my_audit(user_id)
                elif command == "whoami":
                    self.handle_whoami(user_id, session_id)
                
                # System
                elif command == "admin":
                    # Check if user has admin permissions
                    if self.permission_checker.check_permission(user_id, 'list_users'):
                        from admin_console import AdminConsole
                        admin_console = AdminConsole()
                        admin_console.run_admin_console(user_id, session_id)
                        # Refresh menu after returning from admin console
                        session_info = self.session_manager.get_session_info(session_id)
                        if session_info:
                            active_roles = session_info['active_roles']
                        self.display_user_menu(username, active_roles)
                    else:
                        print("Access denied: Insufficient permissions for administrative console")
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
                
                # Refresh session to keep it alive
                self.session_manager.refresh_session(session_id)
                
                # Update active roles in case they changed
                session_info = self.session_manager.get_session_info(session_id)
                if session_info:
                    active_roles = session_info['active_roles']
                
            except KeyboardInterrupt:
                print("\n\nLogging out... Goodbye!")
                from auth import logout_user
                logout_user(session_id)
                return True
            except Exception as e:
                print(f"User console error: {e}")
        
        return False
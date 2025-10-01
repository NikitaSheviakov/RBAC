"""
Admin Console for RBAC System
Provides administrative interface for user, role, and system management
"""
from tabulate import tabulate
from role_manager import RoleManager
from user_manager import UserManager
from session_manager import SessionManager
from constraint_manager import ConstraintManager
from audit import get_audit_logs, get_audit_statistics
from database import get_db_connection

class AdminConsole:
    """
    Administrative interface for RBAC system management
    Provides comprehensive system administration capabilities
    """
    
    def __init__(self):
        self.role_manager = RoleManager()
        self.user_manager = UserManager()
        self.session_manager = SessionManager()
        self.constraint_manager = ConstraintManager()
    
    def display_admin_menu(self):
        """Display administrative menu options"""
        menu = """
ADMINISTRATIVE CONSOLE - Available Commands:

USER MANAGEMENT:
  list_users       - List all users in system
  user_info        - View detailed user information
  create_user      - Create new user account
  deactivate_user  - Deactivate user account
  activate_user    - Activate user account

ROLE MANAGEMENT:
  list_roles       - List all roles and permissions
  assign_role      - Assign role to user
  remove_role      - Remove role from user
  user_roles       - View user's assigned roles

SESSION MANAGEMENT:
  active_sessions  - View active user sessions
  session_info     - Get detailed session information
  end_session      - End user session

CONSTRAINT MANAGEMENT:
  list_constraints - View role constraints
  add_constraint   - Add new role constraint

AUDIT & MONITORING:
  view_audit       - View audit logs
  audit_stats      - System audit statistics
  system_stats     - Overall system statistics

SYSTEM MAINTENANCE:
  cleanup_sessions - Clean up expired sessions
  help             - Show this menu
  back             - Return to main menu
"""
        print(menu)
    
    def handle_list_users(self, admin_id):
        """Display all users in the system"""
        users, error = self.user_manager.list_all_users(admin_id)
        if error:
            print(f"Error: {error}")
            return
        
        if not users:
            print("No users found in system")
            return
        
        table_data = []
        for user in users:
            table_data.append([
                user['id'],
                user['username'],
                user['roles'],
                "Yes" if user['is_super_admin'] else "No",
                "Active" if user['is_active'] else "Inactive",
                user['created_at'][:16]  # Trim to date + hour:minute
            ])
        
        headers = ["ID", "Username", "Roles", "Admin", "Status", "Registered"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal users: {len(users)}")
        
        headers = ["ID", "Username", "Security Level", "Super Admin", "Status", "Registered"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal users: {len(users)}")
    
    def handle_user_info(self, admin_id, user_id=None):
        """Display detailed user information"""
        if not user_id:
            user_input = input("Enter user ID (or leave blank for your info): ").strip()
            if user_input:
                try:
                    user_id = int(user_input)
                except ValueError:
                    print("Error: Please enter a valid user ID")
                    return
            else:
                user_id = admin_id
        
        user_info, error = self.user_manager.get_user_info(admin_id, user_id)
        if error:
            print(f"Error: {error}")
            return
        
        print("\nUSER DETAILED INFORMATION:")
        print("=" * 50)
        for key, value in user_info.items():
            formatted_key = key.replace('_', ' ').title()
            print(f"{formatted_key}: {value}")
        
        # Show assigned roles
        roles = self.role_manager.get_user_roles(user_id)
        print(f"\nAssigned Roles: {', '.join(roles) if roles else 'None'}")
        
        # Show active sessions
        sessions = self.session_manager.get_user_sessions(user_id)
        print(f"Active Sessions: {len(sessions)}")
    
    def handle_create_user(self, admin_id):
        """Create new user account"""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        from auth import register_user
        user_id = register_user(username, password)
        
        if user_id:
            print(f"User '{username}' created successfully with ID: {user_id}")
            
            # Offer to assign additional roles
            assign_more = input("Assign additional roles? (yes/no): ").strip().lower()
            if assign_more == 'yes':
                self.handle_assign_role(admin_id, user_id)
        else:
            print("Failed to create user - username may already exist")
    
    def handle_assign_role(self, admin_id, target_user_id=None):
        """Assign role to user"""
        if not target_user_id:
            try:
                target_user_id = int(input("Enter target user ID: ").strip())
            except ValueError:
                print("Error: Please enter a valid user ID")
                return
        
        # Show available roles
        roles = self.role_manager.get_all_roles()
        print("\nAvailable roles:")
        for role in roles:
            print(f"  - {role['name']}: {role['description']}")
        
        role_name = input("\nEnter role name to assign: ").strip()
        
        success, message = self.role_manager.assign_role_to_user(admin_id, target_user_id, role_name)
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_remove_role(self, admin_id):
        """Remove role from user"""
        try:
            target_user_id = int(input("Enter target user ID: ").strip())
            role_name = input("Enter role name to remove: ").strip()
        except ValueError:
            print("Error: Please enter a valid user ID")
            return
        
        success, message = self.role_manager.remove_role_from_user(admin_id, target_user_id, role_name)
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_list_roles(self, admin_id):
        """Display all roles and their permissions"""
        roles = self.role_manager.get_all_roles()
        
        if not roles:
            print("No roles found in system")
            return
        
        print("\nSYSTEM ROLES AND PERMISSIONS:")
        print("=" * 60)
        
        for role in roles:
            print(f"\nRole: {role['name']}")
            print(f"Description: {role['description']}")
            print(f"Permissions: {', '.join(role['permissions']) if role['permissions'] else 'None'}")
            print("-" * 40)
    
    def handle_user_roles(self, admin_id):
        """View user's assigned roles"""
        try:
            user_id = int(input("Enter user ID: ").strip())
        except ValueError:
            print("Error: Please enter a valid user ID")
            return
        
        roles = self.role_manager.get_user_roles(user_id)
        user_info, error = self.user_manager.get_user_info(admin_id, user_id)
        
        if error:
            print(f"Error: {error}")
            return
        
        print(f"\nRoles assigned to {user_info['username']}:")
        if roles:
            for role in roles:
                permissions = self.role_manager.get_role_permissions(role)
                print(f"  - {role}: {len(permissions)} permissions")
        else:
            print("  No roles assigned")
    
    def handle_active_sessions(self, admin_id):
        """Display active user sessions"""
        users, error = self.user_manager.list_all_users(admin_id)
        if error:
            print(f"Error: {error}")
            return
        
        active_sessions = []
        for user in users:
            sessions = self.session_manager.get_user_sessions(user['id'])
            for session in sessions:
                active_sessions.append({
                    'user_id': user['id'],
                    'username': user['username'],
                    'session_id': session['session_id'],
                    'active_roles': ', '.join(session['active_roles']),
                    'login_time': session['login_time'][:16],
                    'last_activity': session['last_activity'][:16]
                })
        
        if not active_sessions:
            print("No active sessions found")
            return
        
        table_data = []
        for session in active_sessions:
            table_data.append([
                session['user_id'],
                session['username'],
                session['session_id'],
                session['active_roles'],
                session['login_time'],
                session['last_activity']
            ])
        
        headers = ["User ID", "Username", "Session ID", "Active Roles", "Login Time", "Last Activity"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nTotal active sessions: {len(active_sessions)}")
    
    def handle_session_info(self, admin_id):
        """Get detailed session information"""
        try:
            session_id = int(input("Enter session ID: ").strip())
        except ValueError:
            print("Error: Please enter a valid session ID")
            return
        
        session_info = self.session_manager.get_session_info(session_id)
        if not session_info:
            print("Session not found or inactive")
            return
        
        print("\nSESSION DETAILED INFORMATION:")
        print("=" * 50)
        for key, value in session_info.items():
            if key == 'active_roles':
                formatted_value = ', '.join(value) if value else 'None'
            elif key == 'assigned_roles':
                formatted_value = ', '.join(value) if value else 'None'
            else:
                formatted_value = value
            
            formatted_key = key.replace('_', ' ').title()
            print(f"{formatted_key}: {formatted_value}")
    
    def handle_end_session(self, admin_id):
        """End user session"""
        try:
            session_id = int(input("Enter session ID to end: ").strip())
        except ValueError:
            print("Error: Please enter a valid session ID")
            return
        
        success = self.session_manager.end_session(session_id)
        if success:
            print("Session ended successfully")
        else:
            print("Failed to end session - session may not exist")
    
    def handle_list_constraints(self, admin_id):
        """Display all role constraints"""
        constraints = self.constraint_manager.get_all_constraints()
        
        if not constraints:
            print("No role constraints defined")
            return
        
        table_data = []
        for constraint in constraints:
            table_data.append([
                constraint['type'].title(),
                constraint['role1'],
                constraint['role2'],
                constraint['description'] or 'No description'
            ])
        
        headers = ["Type", "Role 1", "Role 2", "Description"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        static_count = len([c for c in constraints if c['type'] == 'static'])
        dynamic_count = len([c for c in constraints if c['type'] == 'dynamic'])
        print(f"\nConstraints: {static_count} static, {dynamic_count} dynamic")
    
    def handle_add_constraint(self, admin_id):
        """Add new role constraint"""
        print("Available constraint types:")
        print("  static  - Users cannot have both roles assigned")
        print("  dynamic - Users cannot activate both roles in same session")
        
        constraint_type = input("Enter constraint type (static/dynamic): ").strip().lower()
        if constraint_type not in ['static', 'dynamic']:
            print("Error: Constraint type must be 'static' or 'dynamic'")
            return
        
        role1 = input("Enter first role name: ").strip()
        role2 = input("Enter second role name: ").strip()
        description = input("Enter constraint description (optional): ").strip()
        
        success, message = self.constraint_manager.add_static_constraint(
            admin_id, role1, role2, description
        )
        
        if success:
            print(f"Success: {message}")
        else:
            print(f"Error: {message}")
    
    def handle_view_audit(self, admin_id):
        """Display audit logs with filtering options"""
        print("\nAudit Log Filter Options:")
        print("1 - All events")
        print("2 - Successful events only")
        print("3 - Failed events only")
        print("4 - User management events")
        print("5 - Role management events")
        print("6 - Object access events")
        
        choice = input("Select filter (1-6): ").strip()
        
        filters = {}
        if choice == "2":
            filters['success'] = True
        elif choice == "3":
            filters['success'] = False
        elif choice == "4":
            filters['event_type'] = 'user_%'
        elif choice == "5":
            filters['event_type'] = 'role_%'
        elif choice == "6":
            filters['event_type'] = 'object_%'
        
        try:
            limit = int(input("Enter number of records to show (default 50): ") or "50")
        except ValueError:
            limit = 50
        
        logs = get_audit_logs(limit=limit, filters=filters)
        
        if not logs:
            print("No audit logs found matching criteria")
            return
        
        table_data = []
        for log in logs:
            table_data.append([
                log['id'],
                log['timestamp'][:16],
                log['username'] or 'System',
                log['event_type'],
                log['object_name'] or '',
                log['details'][:50] + '...' if len(log['details']) > 50 else log['details'],
                "SUCCESS" if log['success'] else "FAILED"
            ])
        
        headers = ["ID", "Timestamp", "User", "Event", "Object", "Details", "Result"]
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        print(f"\nShowing {len(logs)} audit records")
    
    def handle_audit_stats(self, admin_id):
        """Display audit statistics"""
        stats = get_audit_statistics()
        
        print("\nAUDIT STATISTICS:")
        print("=" * 40)
        print(f"Total Events: {stats['total_events']}")
        print(f"Successful: {stats['success_events']}")
        print(f"Failed: {stats['failed_events']}")
        print(f"Last 24h Activity: {stats['last_24h_activity']}")
        
        print("\nEvents by Type:")
        for event_type, count in stats['events_by_type']:
            print(f"  {event_type}: {count}")
    
    def handle_system_stats(self, admin_id):
        """Display comprehensive system statistics"""
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
        
        # Session statistics
        cursor.execute("SELECT COUNT(*) FROM sessions WHERE is_active = 1")
        active_sessions = cursor.fetchone()[0]
        
        # Permission statistics
        cursor.execute("SELECT COUNT(*) FROM permissions")
        total_permissions = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM role_permissions")
        role_permission_assignments = cursor.fetchone()[0]
        
        conn.close()
        
        # Audit statistics
        audit_stats = get_audit_statistics()
        
        print("\nSYSTEM STATISTICS:")
        print("=" * 50)
        
        print(f"\nUSERS:")
        print(f"  Total Users: {total_users}")
        print(f"  Active Users: {active_users}")
        print(f"  Users with Roles: {users_with_roles}")
        
        print(f"\nROLES AND PERMISSIONS:")
        print(f"  Total Roles: {total_roles}")
        print(f"  Total Permissions: {total_permissions}")
        print(f"  Role-Permission Assignments: {role_permission_assignments}")
        
        print(f"\nOBJECTS:")
        print(f"  Total Objects: {total_objects}")
        print(f"  Users with Objects: {users_with_objects}")
        
        print(f"\nSESSIONS:")
        print(f"  Active Sessions: {active_sessions}")
        
        print(f"\nAUDIT:")
        print(f"  Total Events: {audit_stats['total_events']}")
        print(f"  Success Rate: {(audit_stats['success_events']/audit_stats['total_events']*100):.1f}%")
        print(f"  Recent Activity (24h): {audit_stats['last_24h_activity']}")
    
    def handle_cleanup_sessions(self, admin_id):
        """Clean up expired sessions"""
        cleaned_count = self.session_manager.cleanup_expired_sessions()
        print(f"Cleaned up {cleaned_count} expired sessions")
    
    def run_admin_console(self, admin_id, session_id):
        """Run administrative console interface"""
        print("\n" + "=" * 60)
        print("          RBAC SYSTEM - ADMINISTRATIVE CONSOLE")
        print("=" * 60)
        self.display_admin_menu()
        
        while True:
            try:
                command = input(f"\nadmin> ").strip().lower()
                
                if command == "":
                    continue
                elif command == "help":
                    self.display_admin_menu()
                elif command == "back":
                    print("Returning to main menu...")
                    break
                
                # User Management
                elif command == "list_users":
                    self.handle_list_users(admin_id)
                elif command == "user_info":
                    self.handle_user_info(admin_id)
                elif command == "create_user":
                    self.handle_create_user(admin_id)
                elif command == "deactivate_user":
                    self.user_manager.deactivate_user(admin_id, 
                        int(input("Enter user ID to deactivate: ").strip()))
                elif command == "activate_user":
                    self.user_manager.activate_user(admin_id,
                        int(input("Enter user ID to activate: ").strip()))
                
                # Role Management
                elif command == "list_roles":
                    self.handle_list_roles(admin_id)
                elif command == "assign_role":
                    self.handle_assign_role(admin_id)
                elif command == "remove_role":
                    self.handle_remove_role(admin_id)
                elif command == "user_roles":
                    self.handle_user_roles(admin_id)
                
                # Session Management
                elif command == "active_sessions":
                    self.handle_active_sessions(admin_id)
                elif command == "session_info":
                    self.handle_session_info(admin_id)
                elif command == "end_session":
                    self.handle_end_session(admin_id)
                
                # Constraint Management
                elif command == "list_constraints":
                    self.handle_list_constraints(admin_id)
                elif command == "add_constraint":
                    self.handle_add_constraint(admin_id)
                
                # Audit & Monitoring
                elif command == "view_audit":
                    self.handle_view_audit(admin_id)
                elif command == "audit_stats":
                    self.handle_audit_stats(admin_id)
                elif command == "system_stats":
                    self.handle_system_stats(admin_id)
                
                # System Maintenance
                elif command == "cleanup_sessions":
                    self.handle_cleanup_sessions(admin_id)
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
                
                # Refresh session to keep it alive
                self.session_manager.refresh_session(session_id)
                
            except KeyboardInterrupt:
                print("\n\nExiting admin console. Goodbye!")
                break
            except Exception as e:
                print(f"Admin console error: {e}")
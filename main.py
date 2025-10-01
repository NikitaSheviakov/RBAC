"""
Main entry point for RBAC System
Role-Based Access Control System Implementation
"""
from database import init_database
from auth import login_user, register_user
from user_console import UserConsole

def display_welcome():
    """Display welcome message and system information"""
    print("\n" + "=" * 70)
    print("              ROLE-BASED ACCESS CONTROL (RBAC) SYSTEM")
    print("=" * 70)
    print("System Features:")
    print("  • User authentication and session management")
    print("  • Role-based permission system with 5 predefined roles")
    print("  • Object management with access control")
    print("  • Dynamic role activation and constraints")
    print("  • Comprehensive audit logging")
    print("  • Administrative console for system management")
    print("\nDefault admin account: admin / admin123")
    print("=" * 70)

def display_main_menu():
    """Display main menu options"""
    menu = """
MAIN MENU - Available Commands:

  login    - Login to system
  register - Register new user account
  help     - Show this menu
  exit     - Exit system

Type 'login' to begin or 'register' to create new account.
"""
    print(menu)

def main():
    """
    Main function - initializes system and handles user authentication
    """
    try:
        # Initialize database and system
        print("Initializing RBAC System...")
        init_database()
        
        display_welcome()
        display_main_menu()
        
        user_console = UserConsole()
        
        while True:
            try:
                command = input("\nsystem> ").strip().lower()
                
                if command == "":
                    continue
                elif command == "help":
                    display_main_menu()
                elif command == "exit":
                    print("Exiting RBAC System. Goodbye!")
                    break
                
                elif command == "login":
                    username = input("Username: ").strip()
                    password = input("Password: ").strip()
                    
                    user_data = login_user(username, password)
                    if user_data:
                        # Successfully logged in - start user console
                        should_exit = user_console.run_user_console(user_data)
                        if should_exit:
                            break
                        else:
                            # User logged out but system continues
                            display_main_menu()
                    else:
                        print("Login failed. Please check credentials and try again.")
                
                elif command == "register":
                    username = input("Choose username: ").strip()
                    password = input("Choose password: ").strip()
                    
                    user_id = register_user(username, password)
                    if user_id:
                        print(f"Registration successful! User ID: {user_id}")
                        print("You can now login with your credentials.")
                        print("Note: New users are automatically assigned the 'user' role.")
                    else:
                        print("Registration failed. Username may already exist.")
                
                else:
                    print("Unknown command. Type 'help' for available commands.")
            
            except KeyboardInterrupt:
                print("\n\nExiting RBAC System. Goodbye!")
                break
            except Exception as e:
                print(f"System error: {e}")
    
    except Exception as e:
        print(f"Fatal error during system startup: {e}")
        print("Please check system configuration and try again.")

if __name__ == "__main__":
    main()
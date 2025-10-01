"""
Configuration file for RBAC System
Defines roles, permissions and system constants
"""

# System roles configuration
ROLES = {
    'admin': 'System Administrator - full access to all functions',
    'security_officer': 'Security Officer - manages users and roles', 
    'manager': 'Department Manager - manages team objects and users',
    'user': 'Regular User - basic object operations',
    'auditor': 'Auditor - read-only access to system logs and objects'
}

# Permissions configuration
PERMISSIONS = {
    # Object permissions
    'read_object': 'Read object content',
    'write_object': 'Modify object content', 
    'delete_object': 'Delete objects',
    'create_object': 'Create new objects',
    
    # User management permissions
    'list_users': 'View all users',
    'view_user_info': 'View user information',
    'assign_roles': 'Assign roles to users',
    'deactivate_user': 'Deactivate user accounts',
    
    # Role management permissions
    'manage_roles': 'Create and modify roles',
    'view_audit': 'View audit logs',
    'view_statistics': 'View system statistics'
}

# Role-Permission mappings
ROLE_PERMISSIONS = {
    'admin': [
        'read_object', 'write_object', 'delete_object', 'create_object',
        'list_users', 'view_user_info', 'assign_roles', 'deactivate_user',
        'manage_roles', 'view_audit', 'view_statistics'
    ],
    'security_officer': [
        'read_object', 'create_object',
        'list_users', 'view_user_info', 'assign_roles', 'deactivate_user',
        'view_audit'
    ],
    'manager': [
        'read_object', 'write_object', 'create_object',
        'list_users', 'view_user_info'
    ],
    'user': [
        'read_object', 'write_object', 'create_object'
    ],
    'auditor': [
        'read_object', 'list_users', 'view_audit'
    ]
}

# Static role constraints (users cannot have these roles simultaneously)
STATIC_CONSTRAINTS = [
    ('admin', 'auditor'),  # Admin cannot also be auditor
]

# Dynamic role constraints (cannot be active in same session)
DYNAMIC_CONSTRAINTS = [
    ('security_officer', 'auditor'),  # Cannot activate both in same session
]

# System settings
DATABASE_NAME = "rbac_system.db"
SESSION_DURATION = 8 * 60 * 60  # 8 hours in seconds
MAX_LOGIN_ATTEMPTS = 3

# Audit event types
AUDIT_EVENTS = {
    "ROLE_ACTIVATION": "role_activation",
    "SESSION_EXPIRED": "session_expired", 
    "SESSION_END": "session_end",
    "OBJECT_CREATE": "object_create",
    "OBJECT_READ": "object_read",
    "OBJECT_UPDATE": "object_update",
    "OBJECT_DELETE": "object_delete",
    "OBJECT_LIST": "object_list",
    "OBJECT_SEARCH": "object_search",
    "USER_LOGIN": "user_login",
    "USER_LOGOUT": "user_logout",
    "USER_REGISTER": "user_register",
    "ROLE_ASSIGNMENT": "role_assignment", 
    "ROLE_REMOVAL": "role_removal",
    "OBJECT_CREATE": "object_create",
    "OBJECT_READ": "object_read",
    "OBJECT_UPDATE": "object_update",
    "OBJECT_DELETE": "object_delete",
    "PERMISSION_CHECK": "permission_check",
    "SESSION_START": "session_start",
    "SESSION_END": "session_end"
}
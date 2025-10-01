"""
Audit system for RBAC
Logs security events and provides audit functionality
"""
from database import get_db_connection

def log_event(user_id, event_type, role_name=None, object_id=None, details="", success=True):
    """
    Log security event to audit database
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO audit_logs (event_type, user_id, role_name, object_id, details, success) 
            VALUES (?, ?, ?, ?, ?, ?)
        """, (event_type, user_id, role_name, object_id, details, success))
        conn.commit()
    except Exception as e:
        print(f"Audit logging error: {e}")
    finally:
        conn.close()

def get_audit_logs(limit=50, filters=None):
    """
    Retrieve audit logs with optional filtering
    Returns formatted list of audit records
    """
    if filters is None:
        filters = {}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT al.id, al.timestamp, al.event_type, al.details, al.success,
               u.username, al.role_name, o.name as object_name
        FROM audit_logs al
        LEFT JOIN users u ON al.user_id = u.id
        LEFT JOIN objects o ON al.object_id = o.id
        WHERE 1=1
    """
    params = []
    
    # Apply filters
    if filters.get('event_type'):
        query += " AND al.event_type = ?"
        params.append(filters['event_type'])
    
    if filters.get('success') is not None:
        query += " AND al.success = ?"
        params.append(filters['success'])
    
    if filters.get('user_id'):
        query += " AND al.user_id = ?"
        params.append(filters['user_id'])
    
    if filters.get('role_name'):
        query += " AND al.role_name = ?"
        params.append(filters['role_name'])
    
    # Add ordering and limit
    query += " ORDER BY al.timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    logs = cursor.fetchall()
    conn.close()
  

def get_audit_statistics():
    """
    Get statistics about audit events
    Returns dictionary with audit statistics
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total events count
    cursor.execute("SELECT COUNT(*) FROM audit_logs")
    total_events = cursor.fetchone()[0]
    
    # Success/failure count
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE success = 1")
    success_events = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE success = 0")
    failed_events = cursor.fetchone()[0]
    
    # Events by type
    cursor.execute("""
        SELECT event_type, COUNT(*) as count 
        FROM audit_logs 
        GROUP BY event_type 
        ORDER BY count DESC
    """)
    events_by_type = cursor.fetchall()
    
    # Recent activity
    cursor.execute("""
        SELECT COUNT(*) 
        FROM audit_logs 
        WHERE timestamp > datetime('now', '-1 day')
    """)
    last_24h = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_events': total_events,
        'success_events': success_events,
        'failed_events': failed_events,
        'events_by_type': events_by_type,
        'last_24h_activity': last_24h
    }
    return logs
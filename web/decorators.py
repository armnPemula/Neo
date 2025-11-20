from functools import wraps
from flask import abort
from flask_login import current_user

def require_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(403)
            
            if required_role == 'admin' and current_user.role_name != 'admin':
                abort(403)
            elif required_role == 'operator' and current_user.role_name not in ['admin', 'operator']:
                abort(403)
            elif required_role == 'viewer' and current_user.role_name not in ['admin', 'operator', 'viewer']:
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_name != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def operator_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_name not in ['admin', 'operator']:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

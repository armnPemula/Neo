from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
import uuid

bp = Blueprint('auth', __name__)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role_name == 'admin':
            return redirect(url_for('user_management.user_management'))
        else:
            return redirect(url_for('dashboard.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username:
            flash('Username is required', 'danger')
            return render_template('login.html')
        
        if not password:
            flash('Password is required', 'danger')
            return render_template('login.html')
        
        from flask import current_app
        from web.web_app import User
        
        user_info = current_app.user_manager.authenticate(username, password)
        
        if not user_info:
            flash('Invalid username or password', 'danger')
            return render_template('login.html')
        
        user_id = user_info['id']
        print(f"[DEBUG] Authentication successful. User ID: {user_id}")
        print(f"[DEBUG] User info from authenticate: {user_info}")
        
        if not hasattr(current_app, 'memory_users'):
            current_app.memory_users = {}
        
        current_app.memory_users[user_id] = {
            'id': user_id,
            'username': username
        }
        
        user_role = 'viewer'  # Default fallback
        if 'role_name' in user_info:
            user_role = user_info['role_name']
            print(f"[DEBUG] User role from authenticate result: {user_role}")
        else:
            print(f"[DEBUG] No role_name in user_info, using database lookup")
            try:
                from flask import current_app
                db_user = current_app.user_manager.get_user(user_id)
                print(f"[DEBUG] DB user data: {db_user}")
                if db_user and 'role_name' in db_user:
                    user_role = db_user['role_name']
                    print(f"[DEBUG] User role from UserManager: {user_role}")
                else:
                    print(f"[DEBUG] No role found in UserManager user data")
            except Exception as e:
                print(f"Error getting user role: {e}")
        
        print(f"[DEBUG] Creating User with role: {user_role}")
        user = User(user_id, username, user_role)
        print(f"[DEBUG] User object created. Role name: {getattr(user, 'role_name', 'NOT_SET')}")
        login_success = login_user(user, remember=False)
        print(f"[DEBUG] Login success: {login_success}")
        
        if login_success:
            from flask import current_app
            if hasattr(current_app, 'audit_logger') and current_app.audit_logger:
                current_app.audit_logger.log_event(
                    user_id=user_id,
                    action="user.login",
                    resource_type="user_session",
                    resource_id=str(uuid.uuid4()),
                    details=f"User {username} logged in from {request.remote_addr}",
                    ip_address=request.remote_addr
                )
            
            flash(f'Welcome {username}!', 'success')
            next_page = request.args.get('next')
            if current_user.role_name == 'admin':
                return redirect(next_page) if next_page else redirect(url_for('user_management.user_management'))
            else:
                return redirect(next_page) if next_page else redirect(url_for('dashboard.dashboard'))
        else:
            flash('Login failed', 'danger')
    
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id
    
    from flask import current_app
    if hasattr(current_app, 'audit_logger') and current_app.audit_logger:
        current_app.audit_logger.log_event(
            user_id=user_id,
            action="user.logout",
            resource_type="user_session",
            resource_id=str(uuid.uuid4()),
            details=f"User {username} logged out from {request.remote_addr}",
            ip_address=request.remote_addr
        )
    
    from flask import current_app
    if hasattr(current_app, 'memory_users') and user_id in current_app.memory_users:
        del current_app.memory_users[user_id]
    
    logout_user()
    flash(f'Goodbye {username}!', 'info')
    return redirect(url_for('auth.login'))

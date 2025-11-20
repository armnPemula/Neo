from flask import Blueprint, render_template, request, jsonify, current_app, flash
from flask_login import login_required, current_user
from web.decorators import require_role

bp = Blueprint('user_management', __name__, url_prefix='/users')

@bp.route('/')
@login_required
@require_role('admin')
def user_management():
    return render_template('user_management.html')

@bp.route('/api/users/pending', methods=['GET'])
@login_required
@require_role('admin')
def get_pending_users():
    try:
        shared_db = current_app.db
        
        pending_users = shared_db.fetchall('''
            SELECT u.id, u.username, u.email, u.created_at
            FROM users u
            WHERE u.registration_status = 'pending'
            ORDER BY u.created_at DESC
        ''')
        
        return jsonify({
            'success': True,
            'users': [dict(user) for user in pending_users]
        })
    except Exception as e:
        print(f"Error getting pending users: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/users/active', methods=['GET'])
@login_required
@require_role('admin')
def get_active_users():
    try:
        shared_db = current_app.db
        
        active_users = shared_db.fetchall('''
            SELECT u.id, u.username, u.email, u.is_active, u.last_login, u.created_at, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.is_active = 1 AND u.registration_status = 'approved'
            ORDER BY u.last_login DESC, u.created_at DESC
        ''')
        
        return jsonify({
            'success': True,
            'users': [dict(user) for user in active_users]
        })
    except Exception as e:
        print(f"Error getting active users: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@bp.route('/api/users/approve', methods=['POST'])
@login_required
@require_role('admin')
def approve_user():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        role_name = data.get('role', 'viewer')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            })
        
        shared_db = current_app.db
        
        role = shared_db.get_role_by_name(role_name)
        if not role:
            return jsonify({
                'success': False,
                'error': f'Invalid role: {role_name}'
            })
        
        shared_db.execute('''
            UPDATE users 
            SET role_id = ?, registration_status = 'approved', is_active = 1
            WHERE id = ?
        ''', (role['id'], user_id))
        
        if hasattr(current_app, 'audit_logger') and current_app.audit_logger:
            current_app.audit_logger.log_event(
                user_id=current_user.id,
                action="user.approved",
                resource_type="user",
                resource_id=user_id,
                details=f"User approved with {role_name} role by {current_user.username}",
                ip_address=request.remote_addr
            )
        
        return jsonify({
            'success': True,
            'message': f'User approved with {role_name} role'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@bp.route('/api/users/deny', methods=['POST'])
@login_required
@require_role('admin')
def deny_user():
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            })
        
        shared_db = current_app.db
        
        shared_db.execute('''
            UPDATE users 
            SET registration_status = 'denied', is_active = 0
            WHERE id = ?
        ''', (user_id,))
        
        if hasattr(current_app, 'audit_logger') and current_app.audit_logger:
            current_app.audit_logger.log_event(
                user_id=current_user.id,
                action="user.denied",
                resource_type="user",
                resource_id=user_id,
                details=f"User registration denied by {current_user.username}",
                ip_address=request.remote_addr
            )
        
        return jsonify({
            'success': True,
            'message': 'User registration denied'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@bp.route('/api/users/change-role', methods=['POST'])
@login_required
@require_role('admin')
def change_user_role():
    """Change a user's role"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        role_name = data.get('role')
        
        if not user_id or not role_name:
            return jsonify({
                'success': False,
                'error': 'User ID and role are required'
            })
        
        if user_id == current_user.id and role_name != 'admin':
            return jsonify({
                'success': False,
                'error': 'Cannot change your own role from admin'
            })
        
        shared_db = current_app.db
        
        role = shared_db.get_role_by_name(role_name)
        if not role:
            return jsonify({
                'success': False,
                'error': f'Invalid role: {role_name}'
            })
        
        shared_db.execute('''
            UPDATE users 
            SET role_id = ?
            WHERE id = ?
        ''', (role['id'], user_id))
        
        if hasattr(current_app, 'audit_logger') and current_app.audit_logger:
            current_app.audit_logger.log_event(
                user_id=current_user.id,
                action="user.role_changed",
                resource_type="user",
                resource_id=user_id,
                details=f"User role changed to {role_name} by {current_user.username}",
                ip_address=request.remote_addr
            )
        
        return jsonify({
            'success': True,
            'message': f'User role changed to {role_name}'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@bp.route('/api/users/deactivate', methods=['POST'])
@login_required
@require_role('admin')
def deactivate_user():
    """Deactivate a user"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            })
        
        if user_id == current_user.id:
            return jsonify({
                'success': False,
                'error': 'Cannot deactivate yourself'
            })
        
        shared_db = current_app.db
        
        shared_db.execute('''
            UPDATE users 
            SET is_active = 0
            WHERE id = ?
        ''', (user_id,))
        
        if hasattr(current_app, 'audit_logger') and current_app.audit_logger:
            current_app.audit_logger.log_event(
                user_id=current_user.id,
                action="user.deactivated",
                resource_type="user",
                resource_id=user_id,
                details=f"User deactivated by {current_user.username}",
                ip_address=request.remote_addr
            )
        
        return jsonify({
            'success': True,
            'message': 'User deactivated successfully'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

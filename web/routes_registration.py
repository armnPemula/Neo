from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user
from core.models import NeoC2DB
from werkzeug.security import generate_password_hash
from datetime import datetime
import uuid
import re

bp = Blueprint('registration', __name__, url_prefix='/register')

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit"
    return True, "Password is valid"

@bp.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return render_template('register.html')
        
        if not validate_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('register.html')
        
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        shared_db = current_app.db
        
        existing_user = shared_db.get_user_by_username(username)
        if existing_user:
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        shared_db.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_email = shared_db.fetchone('SELECT * FROM users WHERE email = ?', (email,))
        if existing_email:
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        try:
            viewer_role = shared_db.get_role_by_name('viewer')
            if not viewer_role:
                flash('System configuration error', 'error')
                return render_template('register.html')
            
            user_id = str(uuid.uuid4())
            
            hashed_password = generate_password_hash(password)
            
            shared_db.execute('''
                INSERT INTO users (id, username, password_hash, email, role_id, created_at, is_active, registration_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, hashed_password, email, viewer_role['id'], datetime.now(), 0, 'pending'))
            
            flash('Registration request submitted. An admin will review and approve your account.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            flash(f'Registration failed: {str(e)}', 'error')
    
    return render_template('register.html')

@bp.route('/notifications', methods=['GET'])
@login_required
def get_registration_notifications():
    try:
        if current_user.role_name != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        shared_db = current_app.db
        
        pending_users = shared_db.fetchall('''
            SELECT u.id, u.username, u.email, u.created_at
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            WHERE u.registration_status = 'pending'
            ORDER BY u.created_at DESC
        ''')
        
        return jsonify({
            'success': True,
            'pending_registrations': [dict(user) for user in pending_users]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/approve', methods=['POST'])
@login_required
def approve_user():
    try:
        if current_user.role_name != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        user_id = request.json.get('user_id')
        role_name = request.json.get('role', 'viewer')  # Default to viewer
        
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        shared_db = current_app.db
        
        role = shared_db.get_role_by_name(role_name)
        if not role:
            return jsonify({'error': 'Invalid role'}), 400
        
        shared_db.execute('''
            UPDATE users 
            SET role_id = ?, registration_status = 'approved', is_active = 1
            WHERE id = ?
        ''', (role['id'], user_id))
        
        return jsonify({
            'success': True,
            'message': f'User approved with {role_name} role'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@bp.route('/deny', methods=['POST'])
@login_required
def deny_user():
    try:
        if current_user.role_name != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
        
        user_id = request.json.get('user_id')
        reason = request.json.get('reason', 'Registration denied by admin')
        
        if not user_id:
            return jsonify({'error': 'User ID required'}), 400
        
        shared_db = current_app.db
        
        shared_db.execute('''
            UPDATE users 
            SET registration_status = 'denied', is_active = 0
            WHERE id = ?
        ''', (user_id,))
        
        return jsonify({
            'success': True,
            'message': 'User registration denied'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

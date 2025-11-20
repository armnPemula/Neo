from flask import Blueprint, render_template
from flask_login import login_required, current_user

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

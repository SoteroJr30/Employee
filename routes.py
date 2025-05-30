from flask import render_template, request, redirect, url_for, flash, session
from app import app, db
from models import User
from werkzeug.security import generate_password_hash
from datetime import datetime

def login_required(f):
    """Decorator to require login for protected routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for protected routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin():
            flash('Admin access required.', 'error')
            return redirect(url_for('employee_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page - redirect based on login status"""
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_admin():
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            
            flash(f'Welcome back, {user.get_full_name()}!', 'success')
            
            # Redirect based on role
            if user.is_admin():
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('employee_dashboard'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page - only for employees"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        department = request.form.get('department', '')
        position = request.form.get('position', '')
        phone = request.form.get('phone', '')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='employee',
            first_name=first_name,
            last_name=last_name,
            department=department,
            position=position,
            phone=phone
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    total_employees = User.query.filter_by(role='employee').count()
    active_employees = User.query.filter_by(role='employee', is_active=True).count()
    recent_employees = User.query.filter_by(role='employee').order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html', 
                         total_employees=total_employees,
                         active_employees=active_employees,
                         recent_employees=recent_employees)

@app.route('/employee/dashboard')
@login_required
def employee_dashboard():
    """Employee dashboard"""
    user = User.query.get(session['user_id'])
    return render_template('employee_dashboard.html', user=user)

@app.route('/admin/employees')
@admin_required
def manage_employees():
    """Manage employees page"""
    search = request.args.get('search', '')
    department_filter = request.args.get('department', '')
    
    query = User.query.filter_by(role='employee')
    
    if search:
        query = query.filter(
            (User.first_name.contains(search)) |
            (User.last_name.contains(search)) |
            (User.username.contains(search)) |
            (User.email.contains(search))
        )
    
    if department_filter:
        query = query.filter_by(department=department_filter)
    
    employees = query.order_by(User.last_name, User.first_name).all()
    departments = db.session.query(User.department).filter_by(role='employee').distinct().all()
    departments = [d[0] for d in departments if d[0]]
    
    return render_template('manage_employees.html', 
                         employees=employees, 
                         departments=departments,
                         search=search,
                         department_filter=department_filter)

@app.route('/admin/employees/add', methods=['GET', 'POST'])
@admin_required
def add_employee():
    """Add new employee"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        department = request.form.get('department', '')
        position = request.form.get('position', '')
        phone = request.form.get('phone', '')
        address = request.form.get('address', '')
        salary = request.form.get('salary')
        
        # Validation
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('add_employee.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('add_employee.html')
        
        # Create new employee
        employee = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            role='employee',
            first_name=first_name,
            last_name=last_name,
            department=department,
            position=position,
            phone=phone,
            address=address,
            salary=float(salary) if salary else None
        )
        
        db.session.add(employee)
        db.session.commit()
        
        flash(f'Employee {employee.get_full_name()} added successfully!', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('add_employee.html')

@app.route('/admin/employees/<int:employee_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_employee(employee_id):
    """Edit employee details"""
    employee = User.query.get_or_404(employee_id)
    
    if employee.role == 'admin':
        flash('Cannot edit admin users.', 'error')
        return redirect(url_for('manage_employees'))
    
    if request.method == 'POST':
        employee.username = request.form['username']
        employee.email = request.form['email']
        employee.first_name = request.form['first_name']
        employee.last_name = request.form['last_name']
        employee.department = request.form.get('department', '')
        employee.position = request.form.get('position', '')
        employee.phone = request.form.get('phone', '')
        employee.address = request.form.get('address', '')
        employee.salary = float(request.form['salary']) if request.form.get('salary') else None
        employee.is_active = 'is_active' in request.form
        employee.updated_at = datetime.utcnow()
        
        # Update password if provided
        new_password = request.form.get('new_password')
        if new_password:
            employee.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        flash(f'Employee {employee.get_full_name()} updated successfully!', 'success')
        return redirect(url_for('manage_employees'))
    
    return render_template('edit_employee.html', employee=employee)

@app.route('/admin/employees/<int:employee_id>/delete', methods=['POST'])
@admin_required
def delete_employee(employee_id):
    """Delete employee"""
    employee = User.query.get_or_404(employee_id)
    
    if employee.role == 'admin':
        flash('Cannot delete admin users.', 'error')
        return redirect(url_for('manage_employees'))
    
    name = employee.get_full_name()
    db.session.delete(employee)
    db.session.commit()
    
    flash(f'Employee {name} deleted successfully!', 'success')
    return redirect(url_for('manage_employees'))

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.email = request.form['email']
        user.phone = request.form.get('phone', '')
        user.address = request.form.get('address', '')
        user.updated_at = datetime.utcnow()
        
        # Update password if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        if new_password:
            if not current_password or not user.check_password(current_password):
                flash('Current password is incorrect.', 'error')
                return render_template('employee_dashboard.html', user=user, show_edit_form=True)
            
            user.password_hash = generate_password_hash(new_password)
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        
        if user.is_admin():
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('employee_dashboard'))
    
    if user.is_admin():
        return render_template('admin_dashboard.html', user=user, show_edit_form=True)
    else:
        return render_template('employee_dashboard.html', user=user, show_edit_form=True)

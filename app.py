from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Change this in production (use environment variable)

# Database setup
def init_db():
    try:
        print("Initializing database...")
        conn = sqlite3.connect('tasks.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, role TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS tasks
                     (id INTEGER PRIMARY KEY, title TEXT, description TEXT, assigned_to TEXT,
                      assigned_by TEXT, status TEXT, created_at TEXT, due_date TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS notifications
                     (id INTEGER PRIMARY KEY, user TEXT, message TEXT, read BOOLEAN, created_at TEXT)''')

      
        new_users = [
            {'username': 'admin1', 'password': 'adminpass1', 'role': 'manager'},
            {'username': 'manager2', 'password': 'managerpass2', 'role': 'manager'},
            {'username': 'emp1', 'password': 'emppass1', 'role': 'employee'},
            {'username': 'emp2', 'password': 'emppass2', 'role': 'employee'},
            {'username': 'emp3', 'password': 'emppass3', 'role': 'employee'},
            {'username': 'shabeer', 'password': 'shabeer123', 'role': 'manager'},
            {'username': 'samah', 'password': 'samah123', 'role': 'manager'},
            {'username': 'narayanan', 'password': 'Naren123', 'role': 'manager'},
            {'username': 'rishika', 'password': '1608', 'role': 'employee'},
            {'username': 'naveen', 'password': '911', 'role': 'employee'},
            {'username': 'ajay', 'password': 'ajay24', 'role': 'employee'},
            {'username': 'monica', 'password': 'km0607123', 'role': 'employee'},
            {'username': 'edwin', 'password': 'edwin@65', 'role': 'employee'},
            {'username': 'vignesh', 'password': 'vigneshbm', 'role': 'employee'},
        ]

        # Insert users with hashed passwords
        for user in new_users:
            try:
                hashed_password = generate_password_hash(user['password'])
                c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                          (user['username'], hashed_password, user['role']))
            except sqlite3.IntegrityError:
                print(f"User {user['username']} already exists, skipping...")
        
        conn.commit()
        print("Database initialized successfully.")
    except Exception as e:
        print(f"Error initializing database: {e}")
    finally:
        conn.close()

init_db()

# Helper to get DB connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('tasks.db')
        g.db.row_factory = sqlite3.Row
    return g.db

# Close DB connection at the end of each request
@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'db'):
        g.db.close()

# Login route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user and check_password_hash(user['password'], password):
            session['user'] = username
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('index.html')

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    
    # Get tasks
    if session['role'] == 'manager':
        c.execute("SELECT * FROM tasks ORDER BY created_at DESC")
        tasks = c.fetchall()
    else:
        c.execute("SELECT * FROM tasks WHERE assigned_to=? ORDER BY created_at DESC", (session['user'],))
        tasks = c.fetchall()
    
    # Get notifications
    c.execute("SELECT * FROM notifications WHERE user=? AND read=0 ORDER BY created_at DESC", (session['user'],))
    notifications = c.fetchall()
    
    # Get all employees for manager
    if session['role'] == 'manager':
        c.execute("SELECT username FROM users WHERE role='employee'")
        employees = [row['username'] for row in c.fetchall()]
    else:
        employees = []
    
    return render_template('dashboard.html', tasks=tasks, notifications=notifications, employees=employees)

# Assign task (manager only)
@app.route('/assign_task', methods=['POST'])
def assign_task():
    if 'user' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    
    title = request.form['title']
    description = request.form['description']
    assigned_to = request.form['assigned_to']
    due_date = request.form.get('due_date')  # Optional due date
    
    conn = get_db()
    c = conn.cursor()
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT INTO tasks (title, description, assigned_to, assigned_by, status, created_at, due_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (title, description, assigned_to, session['user'], 'pending', created_at, due_date or None))
    
    # Add notification for employee
    message = f"New task assigned: {title}"
    if due_date:
        message += f" (Due: {due_date})"
    c.execute("INSERT INTO notifications (user, message, read, created_at) VALUES (?, ?, ?, ?)",
              (assigned_to, message, 0, created_at))
    
    conn.commit()
    flash('Task assigned successfully')
    return redirect(url_for('dashboard'))

# Mark task as done (employee only)
@app.route('/mark_done/<int:task_id>')
def mark_done(task_id):
    if 'user' not in session or session['role'] != 'employee':
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE tasks SET status='done' WHERE id=? AND assigned_to=?", (task_id, session['user']))
    conn.commit()
    flash('Task marked as done')
    return redirect(url_for('dashboard'))

# Mark notification as read
@app.route('/mark_read/<int:notif_id>')
def mark_read(notif_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE notifications SET read=1 WHERE id=? AND user=?", (notif_id, session['user']))
    conn.commit()
    return redirect(url_for('dashboard'))

# Add new user (manager only)
@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if 'user' not in session or session['role'] != 'manager':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        if role not in ['manager', 'employee']:
            flash('Invalid role selected')
            return redirect(url_for('add_user'))
        
        conn = get_db()
        c = conn.cursor()
        try:
            hashed_password = generate_password_hash(password)
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      (username, hashed_password, role))
            conn.commit()
            flash('User added successfully')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
        finally:
            conn.close()
    
    return render_template('add_user.html')

# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    try:
        print("Attempting to start Flask server...")
        app.run(debug=True)
    except Exception as e:
        print(f"Error starting Flask server: {e}")
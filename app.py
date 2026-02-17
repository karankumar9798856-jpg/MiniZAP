from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from scanner import SecurityScanner  # Import your pro scanner
import os
import time

app = Flask(__name__)
app.secret_key = 'minizap_secret_key_secure_123'

# --- 1. DATABASE CONFIGURATION (User save karne ke liye) ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///minizap.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- 2. USER MODEL (Table structure) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    joined_date = db.Column(db.String(50), default=time.strftime("%b %d, %Y"))

# Server start hone par Database create karein
with app.app_context():
    db.create_all()

# ---------------- ROUTES ----------------

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 🛡️ SECURITY FIX: अगर यूजर पहले से लॉगिन है, तो लॉगिन पेज न दिखाओ
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Database se user dhundein
        user = User.query.filter_by(email=email).first()
        
        # Password Hash check karein
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Email or Password', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered!', 'error')
            return redirect(url_for('login'))

        # Password ko secure banayein (Hashing)
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(name=name, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Error creating account.', 'error')

    return render_template('register.html')

# --- 3. DASHBOARD LOGIC (Updated for Single Page Result) ---
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # 🛡️ SECURITY FIX: बिना लॉगिन के अंदर घुसना मना है
    if 'user_id' not in session:
        flash('Unauthorized Access! Please Login.', 'error')
        return redirect(url_for('login'))
    
    # Variables initialize karein
    scan_results = None
    process_logs = []
    pdf_file = None
    target_url = None
    
    if request.method == 'POST':
        target_url = request.form['target_url']
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url

        try:
            # Scanner run karein
            scanner = SecurityScanner(target_url)
            scan_results, process_logs, pdf_file = scanner.run_scan()
            
            # IMP: Wapas 'dashboard.html' par hi result bhejein
            return render_template('dashboard.html', 
                                   report=scan_results,       
                                   process_logs=process_logs, 
                                   pdf_file=pdf_file,         
                                   target_url=target_url)     
                                   
        except Exception as e:
            flash(f"Error during scan: {str(e)}", 'error')
            return redirect(url_for('dashboard'))

    return render_template('dashboard.html', report=None)

@app.route('/profile')
def profile():
    # 🛡️ SECURITY FIX
    if 'user_id' not in session: return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    user_info = {"name": user.name, "email": user.email, "joined": user.joined_date}
    return render_template('profile.html', user=user_info)

@app.route('/history')
def history():
    # 🛡️ SECURITY FIX
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('history.html')

@app.route('/about')
def about():
    # About page public rakh sakte hain ya login_required, yahan maine logic barkaraar rakha hai
    return render_template('about.html')

@app.route('/logout')
def logout():
    # 🛡️ SECURITY FIX: सेशन पूरी तरह साफ़ करें
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    # Static folder check
    if not os.path.exists('static'):
        os.makedirs('static')
    app.run(debug=True)
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.secret_key = "firsthire_secret"

# ---------------- MYSQL CONFIG ----------------
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'firsthire_db'

# Resume upload folder
UPLOAD_FOLDER = "static/resumes"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

mysql = MySQL(app)

# ---------------- BASIC PAGES ----------------
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/PrivacyPolicy')
def PrivacyPolicy():
    return render_template('PrivacyPolicy.html')

# ---------------- AUTH ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            return redirect(url_for('jobs'))

        return render_template('login.html', error="Invalid email or password")

    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():

    # ✅ STEP 1: Only set session ONCE (if not already set)
    if 'reset_email' not in session:
        email_from_url = request.args.get('email')
        if email_from_url:
            session['reset_email'] = email_from_url.strip()

    # ✅ STEP 2: Always read email ONLY from session
    email = session.get('reset_email')

    if not email:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            return render_template(
                'forgot_password.html',
                email=email,
                error="Passwords do not match"
            )

        hashed_password = generate_password_hash(new_password)

        cur = mysql.connection.cursor()
        cur.execute(
            "UPDATE users SET password=%s WHERE email=%s",
            (hashed_password, email)
        )
        mysql.connection.commit()
        cur.close()

        # ✅ STEP 3: CLEAR session after success
        session.pop('reset_email', None)

        return redirect(url_for('login'))

    return render_template('forgot_password.html', email=email)

@app.route('/api/update-password', methods=['POST'])
def update_password():
    if 'user_id' not in session:
        return jsonify({
            'success': False,
            'message': 'Unauthorized'
        }), 401

    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({
            'success': False,
            'message': 'Password missing'
        }), 400

    # 🔐 Hash new password
    hashed_password = generate_password_hash(new_password)

    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed_password, session['user_id'])
    )
    mysql.connection.commit()
    cur.close()

    # 🔒 LOGOUT USER AFTER PASSWORD CHANGE
    session.clear()

    # ✅ Send redirect instruction to frontend
    return jsonify({
        'success': True,
        'message': 'Password updated successfully. Please login again.',
        'redirect': url_for('login')
    })




@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")

        hashed_password = generate_password_hash(password)

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# ---------------- DASHBOARD notification ----------------

@app.route('/api/notifications')
def get_notifications():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT id, message
        FROM notifications
        WHERE user_id=%s AND is_read=0
        ORDER BY created_at DESC
        LIMIT 10
    """, (session['user_id'],))

    rows = cur.fetchall()
    cur.close()

    notifications = [
        {"id": r[0], "message": r[1]}
        for r in rows
    ]

    return jsonify(notifications)

@app.route('/api/notifications/read', methods=['POST'])
def mark_notifications_read():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    cur = mysql.connection.cursor()
    cur.execute("""
        UPDATE notifications
        SET is_read=1
        WHERE user_id=%s
    """, (session['user_id'],))
    mysql.connection.commit()
    cur.close()

    return jsonify({"success": True})

@app.route('/api/notifications/count')
def notification_count():
    if 'user_id' not in session:
        return jsonify({'count': 0})

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT COUNT(*) FROM notifications
        WHERE user_id=%s AND is_read=0
    """, (session['user_id'],))
    count = cur.fetchone()[0]
    cur.close()

    return jsonify({'count': count})
@app.route('/api/notifications/unread-count')
def unread_notifications_count():
    if 'user_id' not in session:
        return jsonify({"count": 0})

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT COUNT(*) 
        FROM notifications 
        WHERE user_id=%s AND is_read=0
    """, (session['user_id'],))

    count = cur.fetchone()[0]
    cur.close()

    return jsonify({"count": count})

# ---------------- SETTINGS ----------------
@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('settings.html')

# ---------------- PROFILE ----------------
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html')

# ---------------- PROFILE APIs ----------------
@app.route('/api/profile')
def get_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    uid = session['user_id']
    cur = mysql.connection.cursor()

    cur.execute("SELECT name, email, bio, resume FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()

    cur.execute("SELECT skill FROM skills WHERE user_id=%s", (uid,))
    skills = [s[0] for s in cur.fetchall()]
    cur.close()

    return jsonify({
        "name": user[0],
        "email": user[1],
        "bio": user[2] or "",
        "resume": user[3],
        "skills": skills
    })


@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({"success": False}), 401

    data = request.json
    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE users SET name=%s, bio=%s WHERE id=%s",
        (data.get("name"), data.get("bio"), session['user_id'])
    )
    mysql.connection.commit()
    cur.close()

    session['user_name'] = data.get("name")
    return jsonify({"success": True})


@app.route('/api/upload-resume', methods=['POST'])
def upload_resume():
    if 'user_id' not in session:
        return jsonify({"success": False}), 401

    file = request.files.get("resume")
    if not file:
        return jsonify({"success": False}), 400

    filename = secure_filename(file.filename)
    path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(path)

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET resume=%s WHERE id=%s", (filename, session['user_id']))
    mysql.connection.commit()
    cur.close()

    return jsonify({"success": True, "filename": filename})


@app.route('/api/add-skill', methods=['POST'])
def add_skill():
    if 'user_id' not in session:
        return jsonify({"success": False}), 401

    skill = request.json.get("skill")
    if not skill:
        return jsonify({"success": False}), 400

    cur = mysql.connection.cursor()
    cur.execute("INSERT INTO skills (user_id, skill) VALUES (%s, %s)", (session['user_id'], skill))
    mysql.connection.commit()
    cur.close()

    return jsonify({"success": True})




# ---------------- JOBS (SEARCH + FILTER) ----------------
@app.route('/jobs')
def jobs():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    keyword = request.args.get('q', '').strip()
    industry = request.args.get('industry', '').strip()
    job_type = request.args.get('type', '').strip()

    query = "SELECT * FROM jobs WHERE 1=1"
    params = []

    if keyword:
        query += " AND title LIKE %s"
        params.append(f"%{keyword}%")

    if industry:
        query += " AND industry=%s"
        params.append(industry)

    if job_type:
        query += " AND type=%s"
        params.append(job_type)

    cur = mysql.connection.cursor()
    cur.execute(query, params)
    jobs = cur.fetchall()
    cur.close()

    return render_template('jobs.html', jobs=jobs)

# ---------------- APPLY ----------------
@app.route('/api/apply-job', methods=['POST'])
def api_apply_job():
    if 'user_id' not in session:
        return {'success': False, 'message': 'Unauthorized'}, 401

    data = request.get_json()
    job_id = data.get('job_id')
    user_id = session['user_id']

    if not job_id:
        return {'success': False, 'message': 'Job ID missing'}, 400

    try:
        cur = mysql.connection.cursor()

        # Prevent duplicate application
        cur.execute(
            "SELECT id FROM applications WHERE user_id=%s AND job_id=%s",
            (user_id, job_id)
        )
        if cur.fetchone():
            cur.close()
            return {'success': False, 'message': 'Already applied'}, 409

        # 🔹 Get Job Title
        cur.execute("SELECT title FROM jobs WHERE id=%s", (job_id,))
        job = cur.fetchone()
        job_title = job[0] if job else "this job"

        # Insert application
        cur.execute(
            "INSERT INTO applications (user_id, job_id, status) VALUES (%s, %s, 'Applied')",
            (user_id, job_id)
        )

        # 🔔 Insert notification with job title
        cur.execute("""
            INSERT INTO notifications (user_id, message, is_read)
            VALUES (%s, %s, 0)
        """, (
            user_id,
            f"✅ You have successfully applied for {job_title}"
        ))

        mysql.connection.commit()
        cur.close()

        return {'success': True}, 200

    except Exception as e:
        print("Apply Job Error:", e)
        return {'success': False, 'message': 'Server error'}, 500


@app.route('/apply/<int:job_id>')
def apply(job_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    cur = mysql.connection.cursor()

    # Prevent duplicate apply
    cur.execute(
        "SELECT id FROM applications WHERE user_id=%s AND job_id=%s",
        (user_id, job_id)
    )
    if cur.fetchone():
        cur.close()
        return redirect(url_for('applications'))

    # 🔹 Get Job Title
    cur.execute("SELECT title FROM jobs WHERE id=%s", (job_id,))
    job = cur.fetchone()
    job_title = job[0] if job else "this job"

    # Insert application
    cur.execute(
        "INSERT INTO applications (user_id, job_id, status) VALUES (%s, %s, 'Applied')",
        (user_id, job_id)
    )

    # 🔔 Insert notification
    cur.execute("""
        INSERT INTO notifications (user_id, message, is_read)
        VALUES (%s, %s, 0)
    """, (
        user_id,
        f"✅ You have successfully applied for {job_title}"
    ))

    mysql.connection.commit()
    cur.close()

    return redirect(url_for('applications'))


# ---------------- APPLICATIONS ----------------
@app.route('/applications')
def applications():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT jobs.title, applications.status
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.user_id = %s
    """, (session['user_id'],))
    data = cur.fetchall()
    cur.close()

    return render_template('applications.html', data=data)

@app.route('/api/my-applications')
def api_my_applications():
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT jobs.title, applications.status
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.user_id = %s
        ORDER BY applications.id DESC
    """, (session['user_id'],))
    data = cur.fetchall()
    cur.close()

    return {'applications': data}
@app.route('/api/recent-applications')
def api_recent_applications():
    if 'user_id' not in session:
        return {'error': 'Unauthorized'}, 401

    cur = mysql.connection.cursor()
    cur.execute("""
        SELECT jobs.title, applications.status
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.user_id = %s
        ORDER BY applications.id DESC
        LIMIT 5
    """, (session['user_id'],))
    data = cur.fetchall()
    cur.close()

    return {'recent': data}


# ---------------- INTERNSHIPS ----------------
@app.route('/internships')
def internships():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM jobs WHERE type='Internship'")
    jobs = cur.fetchall()
    cur.close()
    return render_template('Internships.html', jobs=jobs)

# ---------------- TRAININGS ----------------
@app.route('/trainings')
def trainings():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM jobs WHERE type='Training'")
    jobs = cur.fetchall()
    cur.close()
    return render_template('trainings.html', jobs=jobs)

# ---------------- INDUSTRY PAGES ----------------
def industry_page(industry, template):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM jobs WHERE industry=%s", (industry,))
    jobs = cur.fetchall()
    cur.close()
    return render_template(template, jobs=jobs)

@app.route('/it')
def it():
    return industry_page("IT", "it.html")

@app.route('/manufacturing')
def manufacturing():
    return industry_page("Manufacturing", "manufacturing.html")

@app.route('/healthcare')
def healthcare():
    return industry_page("Healthcare", "healthcare.html")

@app.route('/eee')
def eee():
    return industry_page("EEE", "eee.html")

@app.route('/government')
def government():
    return industry_page("Government", "government.html")

@app.route('/social')
def social():
    return industry_page("Social", "social.html")

# ---------------- BANKING ----------------
@app.route('/banking')
def banking():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return industry_page("Banking", "banking.html")


@app.route('/learn-more')
def learn_more():
    return render_template('learn_more.html')


from flask import jsonify

@app.route('/api/dashboard-data')
def dashboard_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    user_id = session['user_id']
    cur = mysql.connection.cursor()

    # ---- COUNTS ----
    cur.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=%s",
        (user_id,)
    )
    applied = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=%s AND status='Shortlisted'",
        (user_id,)
    )
    shortlisted = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=%s AND status='Interview'",
        (user_id,)
    )
    interview = cur.fetchone()[0]

    cur.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=%s AND status='Offer'",
        (user_id,)
    )
    offer = cur.fetchone()[0]

    # ✅ ADD THIS (VERY IMPORTANT)
    cur.execute(
        "SELECT COUNT(*) FROM applications WHERE user_id=%s AND status='Rejected'",
        (user_id,)
    )
    rejected = cur.fetchone()[0]

    # ---- RECENT 5 APPLICATIONS ----
    cur.execute("""
        SELECT jobs.title, applications.status
        FROM applications
        JOIN jobs ON applications.job_id = jobs.id
        WHERE applications.user_id = %s
        ORDER BY applications.id DESC
        LIMIT 5
    """, (user_id,))

    recent_rows = cur.fetchall()

    recent = [
        {
            "title": row[0],
            "status": row[1]
        }
        for row in recent_rows
    ]

    cur.close()

    return jsonify({
        "counts": {
            "applied": applied,
            "shortlisted": shortlisted,
            "interview": interview,
            "offer": offer,
            "rejected": rejected   # ✅ FIXED
        },
        "recent": recent
    })



# ---------------- CONTEXT ----------------
@app.context_processor
def inject_user():
    return dict(user_name=session.get('user_name'))

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(debug=True)

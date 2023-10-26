# myapp/app/routes.py
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import login_required, current_user
from app.models import ShiftUpdate, CriticalUpdates, User, Tracker, InfraChanges, KnowledgeBase, CommandCenter, DebugLog, Website
from app.db import db
from app.db import Session
from flask_login import login_user, logout_user, login_required, LoginManager, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pandas as pd
import logging
import pytz
import io
import os, csv
from io import BytesIO
from io import StringIO
from pyotp import TOTP
from pyotp import random_base32
import pyotp
import qrcode
app = Flask(__name__)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.init_app(app)

app.secret_key = 'Kf}>NPGv2er<;P,z?U8x01}c'

app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)



# Configure the logger to write to a file
log_handler = logging.FileHandler("/var/log/myapp.log")
log_handler.setLevel(logging.INFO)  # Set the desired logging level
app.logger.addHandler(log_handler)

# Now, you can log messages using the app logger
app.logger.info("This is a log message.")


# Modify the function to generate an OTP secret
def generate_otp_secret():
    return random_base32()

# Modify the function to generate a QR code for the secret key
def generate_qr_code(secret, username, issuer):
    totp = TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name=issuer)
    img = qrcode.make(uri)
    img.save('static/qr_codes/{}.png'.format(username))



@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, User.DoesNotExist):
        return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        password_hash = generate_password_hash(password)

        # Check if 2FA is enabled
        enable_2fa = 'enable_2fa' in request.form

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('User already exists. Please choose a different username.', 'error')
        else:
            new_user = User(username=username, password=password_hash, email=email)

            if enable_2fa:
                # Generate and store an OTP secret
                new_user.otp_secret = pyotp.random_base32()  # Use your method to generate OTP secrets
                new_user.is_2fa_enabled = 1  # Enable 2FA

                # Generate a provisioning URI and save the QR code image
                uri = pyotp.totp.TOTP(new_user.otp_secret).provisioning_uri(username, issuer_name='ShiftPortal')
                img = qrcode.make(uri)
                img.save('/root/{}.png'.format(username))  # Change this to your file path

            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')


'''@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')'''


@app.route('/enable_2fa', methods=['GET', 'POST'])
@login_required
def enable_2fa():
    if request.method == 'POST':
        # Generate a secret key
        secret = pyotp.random_base32()

        # Store the secret key in the user's model
        current_user.otp_secret = secret
        current_user.is_2fa_enabled = True
        db.session.commit()

        # Generate a provisioning URI and QR code
        # Generate a provisioning URI and QR code
        # Generate a provisioning URI and QR code
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            current_user.username, issuer_name='ShiftPortal')
        img = qrcode.make(uri)
        img.save('static/qr_code.png')  # Save the QR code

        return render_template('enable_2fa_success.html')

    return render_template('enable_2fa.html')


@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user is not None:
            if check_password_hash(user.password, password):

                session['entered_username'] = username
                session['entered_password'] = password
                user.login_time = datetime.utcnow()
                db.session.commit()
                if user.is_2fa_enabled:
                    if user.otp_secret:
                        otp = pyotp.TOTP(user.otp_secret)
                        if 'otp' in request.form:
                            if otp.verify(request.form.get('otp')):
                                login_user(user, remember=True)
                                return redirect(url_for('home'))
                            else:
                                flash('Invalid OTP', 'danger')
                        else:
                            return render_template('login.html', show_otp=True, authenticated=True)
                    else:
                        flash('2FA is enabled but no OTP secret is set', 'danger')
                else:
                    #login_user(user, remember=True)
                    flash('Unautharized access reach Admin for 2FA', 'danger')
                    return redirect(url_for('login'))
            else:
                flash("Invalid username or password", "danger")
        else:
            flash("Invalid username or password", "danger")

    return render_template('login.html')



@app.route('/two_factor_auth', methods=['GET', 'POST'])
@login_required
def two_factor_auth():
    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            # 2FA verification successful
            current_user.is_2fa_enabled = True
            db.session.commit()
            flash('Two-factor authentication enabled!', 'success')
            #return redirect(url_for('shift_updates'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')
    return render_template('two_factor_auth.html')


@app.route('/verify_otp/<username>', methods=['POST'])
@login_required
def verify_otp(username):
    user = User.query.filter_by(username=username).first()
    otp = pyotp.TOTP(user.otp_secret)

    if otp.verify(request.form.get('otp')):
        login_user(user, remember=True)  # Enable "Remember Me"
        flash('Login successful', 'success')
        #return redirect(url_for('shift_updates'))
    else:
        flash('Invalid OTP', 'danger')
        return render_template('enter_otp.html', user=user)

@app.route('/account_details')
@login_required
def account_details():
    # Assuming your User model has a 'login_time' attribute

    email = current_user.email
    utc_login_time = current_user.login_time

    # Define timezone objects for UTC and IST
    utc_timezone = pytz.timezone('UTC')
    ist_timezone = pytz.timezone('Asia/Kolkata')

    utc_login_time = utc_timezone.localize(utc_login_time)

    # Convert UTC login time to IST
    ist_login_time = utc_login_time.astimezone(ist_timezone)

    return render_template('account_details.html', login_time=ist_login_time, email=email)
#@app.route('/')
#def home():
 #   if current_user.is_authenticated:
  #      return f'Welcome, {current_user.username}! You are logged in. <a href="/logout">Logout</a>'
   # else:
    #    return 'Home Page'

@app.route('/user_profile')
@login_required  # Use the @login_required decorator to protect this route
def user_profile():

    #user = current_user  # Get the current logged-in user (you should have this user object available)
    user = current_user.username


    return render_template('user_profile.html', user=current_user.username)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New password and confirm password do not match', 'danger')
        else:
            # Hash and update the user's password
            current_user.password = generate_password_hash(new_password)

            # Save the updated user in your database

            flash('Password changed successfully', 'success')
            db.session.commit()
            return redirect(url_for('user_profile'))

    return render_template('change_password.html')

# Flag to indicate maintenance status
under_maintenance = False

@app.route('/maintenance')
def maintenance():
    return render_template('maintenance.html')

@app.context_processor
def utility_processor():
    # Create a dictionary for error messages
    error_messages = {
        'not_found_error': 'The page you are looking for does not exist.',
        'server_error': 'Internal Server Error. Please try again later.',
        # Add more error messages as needed
    }

    # Return the error messages as part of the context
    return dict(error_messages=error_messages)


@app.route('/')
@login_required
def index():
    # Get the current date
    current_date = datetime.now()

    # Format the date as dd/mm/yyyy
    formatted_date = current_date.strftime('%d/%m/%Y')

    # Query the database to get shift updates and order them by date
    updates = ShiftUpdate.query.order_by(ShiftUpdate.date.desc()).all()

    if under_maintenance:
        return redirect(url_for('maintenance'))

    if current_user.is_authenticated:
        # Query the database to get the list of websites and SSL certificate expiry dates
        websites = Website.query.all()
        return render_template('home.html', updates=updates, websites=websites, formatted_date=formatted_date)
    else:
        return 'Home Page'

@app.route('/home')
@login_required
def shift_updates():
    return render_template('home.html')



@app.route('/add_website', methods=['GET','POST'])
def add_website():
    if request.method == 'POST':
        name = request.form['name']
        expiry_date = request.form['expiry_date']
        jira_id = request.form['jira_id']
        status = request.form['status']

        website = Website(name=name, expiry_date=expiry_date, jira_id=jira_id, status=status)
        db.session.add(website)
        db.session.commit()

    #return redirect(url_for('index'))  # Redirect back to the homepage
    return render_template('add_website.html')

@app.route('/ssl_expiry', methods=['GET'])
def ssl_expiry():
    # Retrieve the list of websites and their SSL certificate information
    websites = Website.query.all()  # Assuming you have a Website model

    return render_template('ssl_expiry.html', websites=websites)  # Display the notifications on the homepage



# Flask route to update status
@app.route('/update_status/<int:website_id>', methods=['POST'])
def update_status(website_id):
    # Retrieve the website based on website_id
    website = Website.query.get(website_id)

    if not website:
        # Handle the case where the website doesn't exist
        flash("Website not found", "error")
        return redirect(url_for('ssl_expiry'))

    selected_status = request.form.get('status')

    if website.status == 'Done' and selected_status != 'Done':
        flash("Cannot change the status it is already marked as 'Done'", "error")
        return redirect(url_for('ssl_expiry'))

    # Update the status based on the selected option
    website.status = selected_status

    # Commit the changes to the database
    db.session.commit()

    flash("Status updated successfully", "success")
    return redirect(url_for('ssl_expiry'))



@app.route('/view_shift_updates')
@login_required
def view_shift_updates():
    # Get the current date
    current_date = datetime.now()

    # Format the date as dd/mm/yyyy
    formatted_date = current_date.strftime('%d/%m/%Y')

    # Query the database to get shift updates and order them by date
    updates = ShiftUpdate.query.order_by(ShiftUpdate.date.desc()).all()

    return render_template('view_shift_updates.html', updates=updates, formatted_date=formatted_date)


@app.route('/view_updates', methods=['GET', 'POST'])
@login_required
def view_updates():
    date = request.args.get('date')
    shift_type = request.args.get('shift_type')

    current_date = datetime.today().strftime('%Y-%m-%d')

    session['selected_date'] = date
    session['shift_type'] = shift_type

    # Query the database to get updates based on the selected date and shift type
    updates = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).all()

    selected_date = session.get('selected_date', 'yyyy-MM-dd')
    selected_shift_type = session.get('shift_type')

    return render_template('view_updates.html', updates=updates, selected_date=selected_date, selected_shift_type=selected_shift_type, current_date=current_date)


@app.route('/add_update', methods=['GET', 'POST'])
@login_required
def add_update():
    current_date = datetime.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        date = request.form['date']
        shift_type = request.form['shift_type']

        # Extract form field values from request.form
        done_in_shift = request.form['done_in_shift']
        update_to_next_shift = request.form['update_to_next_shift']
        alerts_handled = request.form.get('alerts_handled')
        actioned_alerts = request.form.get('actioned_alerts')
        manual_restarts = request.form.get('manual_restarts')
        tasks = request.form.get('tasks')
        resolved_tasks = request.form.get('resolved_tasks')
        closed_tasks = request.form.get('closed_tasks')
        dev_requests_calls = request.form.get('dev_requests_calls')
        dev_requests_pi_calls = request.form.get('dev_requests_pi_calls')
        dev_requests_debug_loggers = request.form.get('dev_requests_debug_loggers')
        dev_requests_noise = request.form.get('dev_requests_noise')
        dev_requests_jar_replace = request.form.get('dev_requests_jar_replace')
        dev_requests_replicas = request.form.get('dev_requests_replicas')
        dev_requests_threads = request.form.get('dev_requests_threads')
        db_queries_single = request.form.get('db_queries_single')
        db_queries_all_pods = request.form.get('db_queries_all_pods')
        jira_so_tickets = request.form.get('jira_so_tickets')
        jira_ops_to_engg = request.form.get('jira_ops_to_engg')
        capacity_changes = request.form.get('capacity_changes')
        activity = request.form.get('activity')
        db_loads = request.form.get('db_loads')
        follow_ups = request.form.get('follow_ups')

        existing_update = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).first()

        if existing_update:
            error_message = "A record with the same date and shift type already exists."
            return render_template('add_update.html', error_message=error_message)

        # Define p0_updates and p1_updates initially

        shift_update = ShiftUpdate(
            date=date,
            shift_type=shift_type,
            done_in_shift=done_in_shift,
            update_to_next_shift=update_to_next_shift,
            alerts_handled=alerts_handled,
            actioned_alerts=actioned_alerts,
            manual_restarts=manual_restarts,
            tasks=tasks,
            resolved_tasks=resolved_tasks,
            closed_tasks=closed_tasks,
            dev_requests_calls=dev_requests_calls,
            dev_requests_pi_calls=dev_requests_pi_calls,
            dev_requests_debug_loggers=dev_requests_debug_loggers,
            dev_requests_noise=dev_requests_noise,
            dev_requests_jar_replace=dev_requests_jar_replace,
            dev_requests_replicas=dev_requests_replicas,
            dev_requests_threads=dev_requests_threads,
            db_queries_single=db_queries_single,
            db_queries_all_pods=db_queries_all_pods,
            jira_so_tickets=jira_so_tickets,
            jira_ops_to_engg=jira_ops_to_engg,
            capacity_changes=capacity_changes,
            activity=activity,
            db_loads=db_loads,
            follow_ups=follow_ups,
            shift_engineer=current_user.username  # Set shift_engineer to the username of the current user
        )

        db.session.add(shift_update)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('add_update.html', current_date=current_date)




@app.route('/edit_by_date_shift', methods=['GET', 'POST'])
@login_required
def edit_by_date_shift():
    current_date = datetime.today().strftime('%Y-%m-%d')

    if request.method == 'POST':
        date = request.form['date']
        shift_type = request.form['shift_type']

        # Redirect to the edit page for the selected date and shift type
        return redirect(url_for('edit_update', date=date, shift_type=shift_type))

    return render_template('edit_by_date_shift.html', current_date=current_date)

@app.route('/get_data', methods=['POST'])
@login_required
def get_data():
    date = request.form['date']
    shift_type = request.form['shift_type']

    # Query the database using SQLAlchemy to retrieve data based on date and shift_type
    existing_data = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).first()

    if existing_data:
        data_dict = {
            'id': existing_data.id,
            'date': existing_data.date,
            'shift_type': existing_data.shift_type,
            'p0_updates': existing_data.p0_updates,
            'p1_updates': existing_data.p1_updates,
            'done_in_shift': existing_data.done_in_shift,
            'update_to_next_shift': existing_data.update_to_next_shift,
            'pod_issues': existing_data.pod_issues,
            'alerts_handled': existing_data.alerts_handled,
            'actioned_alerts': existing_data.actioned_alerts,
            'manual_restarts': existing_data.manual_restarts,
            'tasks': existing_data.tasks,
            'resolved_tasks': existing_data.resolved_tasks,
            'closed_tasks': existing_data.closed_tasks,
            'dev_requests_calls': existing_data.dev_requests_calls,
            'dev_requests_pi_calls': existing_data.dev_requests_pi_calls,
            'dev_requests_debug_loggers': existing_data.dev_requests_debug_loggers,
            'dev_requests_noise': existing_data.dev_requests_noise,
            'dev_requests_jar_replace': existing_data.dev_requests_jar_replace,
            'dev_requests_replicas': existing_data.dev_requests_replicas,
            'dev_requests_threads': existing_data.dev_requests_threads,
            'db_queries_single': existing_data.db_queries_single,
            'db_queries_all_pods': existing_data.db_queries_all_pods,
            'jira_so_tickets': existing_data.jira_so_tickets,
            'jira_ops_to_engg': existing_data.jira_ops_to_engg,
            'capacity_changes': existing_data.capacity_changes,
            'activity': existing_data.activity,
            'db_loads': existing_data.db_loads,
            'follow_ups': existing_data.follow_ups,
            'shift_engineer': existing_data.shift_engineer
        }
        return jsonify(data_dict)
    else:
        return jsonify({})  # Return an empty JSON response if no data is found


@app.route('/edit_update', methods=['GET', 'POST'])
@login_required
def edit_update():
    current_date = datetime.today().strftime('%Y-%m-%d')

    if request.method == 'GET':
        date = request.args.get('date')
        shift_type = request.args.get('shift_type')

        # Query the database to get the update for the selected date and shift type
        update = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).first()

        return render_template('edit_update.html', update=update)

    elif request.method == 'POST':
        # Handle the form submission to update the selected data
        date = request.form['date']
        shift_type = request.form['shift_type']

        # Query the database to get the update for the selected date and shift type
        update = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).first()

        if update:
            # Update the fields of the existing record
            update.done_in_shift = request.form['done_in_shift']
            update.update_to_next_shift = request.form['update_to_next_shift']
            update.alerts_handled = request.form['alerts_handled']
            update.actioned_alerts = request.form['actioned_alerts']
            update.manual_restarts = request.form['manual_restarts']
            update.tasks = request.form['tasks']
            update.resolved_tasks = request.form['resolved_tasks']
            update.closed_tasks = request.form['closed_tasks']
            update.dev_requests_calls = request.form['dev_requests_calls']
            update.dev_requests_pi_calls = request.form['dev_requests_pi_calls']
            update.dev_requests_debug_loggers = request.form['dev_requests_debug_loggers']
            update.dev_requests_noise = request.form['dev_requests_noise']
            update.dev_requests_jar_replace = request.form['dev_requests_jar_replace']
            update.dev_requests_replicas = request.form['dev_requests_replicas']
            update.dev_requests_threads = request.form['dev_requests_threads']
            update.db_queries_single = request.form['db_queries_single']
            update.db_queries_all_pods = request.form['db_queries_all_pods']
            update.jira_so_tickets = request.form['jira_so_tickets']
            update.jira_ops_to_engg = request.form['jira_ops_to_engg']
            update.capacity_changes = request.form['capacity_changes']
            update.activity = request.form['activity']
            update.db_loads = request.form['db_loads']
            update.follow_ups = request.form['follow_ups']
            update.shift_engineer = request.form['shift_engineer']

            db.session.commit()

        return redirect(url_for('index'))

    return render_template('edit_update.html', current_date=current_date)


@app.route('/get_by_date_shift', methods=['GET', 'POST'])
@login_required
def get_by_date_shift():
    if request.method == 'POST':
        date = request.form['date']
        shift_type = request.form['shift_type']

        # Redirect to the view update page for the selected date and shift type
        return redirect(url_for('get_update', date=date, shift_type=shift_type))

    return render_template('get_by_date_shift.html')


#############################################get-update############################################################

@app.route('/get_update', methods=['GET', 'POST'])
@login_required
def get_update():
    if request.method == 'GET':
        date = request.args.get('date')
        shift_type = request.args.get('shift_type')

        # Query the database to get the update for the selected date and shift type
        update = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).first()

        return render_template('get_update.html', update=update)

    return render_template('get_update.html')


# Define the 'CSV_DOWNLOAD_FOLDER' configuration key
app.config['CSV_DOWNLOAD_FOLDER'] = '/root/project1/'


import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
@app.route('/email_update', methods=['GET', 'POST'])
@login_required
def email_update():

    # Get the data from the request (you can replace this with your own method to obtain the data)
    date = request.args.get('date')
    shift_type = request.args.get('shift_type')

    # Query the database to get the update for the selected date and shift type
    update = ShiftUpdate.query.filter_by(date=date, shift_type=shift_type).first()
    print(update)

    # Create the HTML content for the email
    html_content = render_template('email_updates.html', update=update)

    # Email configuration
    to_email = 'ymanikanta6264@gmail.com'  # Replace with your Gmail email
    from_email = 'manikanta241@gmail.com'  # Replace with the recipient's email
    email_subject = 'Shift Update Report'
    password = 'Manii$5432@'

    # Create a MIMEText object for the HTML content
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = email_subject
    msg.attach(MIMEText(html_content, 'html'))

    print("----------------------")
    # Send the email using Gmail's SMTP server
    try:
        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login(from_email, 'rtlq lylm ueap xeeg')  # Replace with your Gmail email and password
        smtp_server.sendmail(from_email, to_email, msg.as_string())
        smtp_server.quit()
        flash('Email sent successfully', 'success')
        return redirect(url_for('view_shift_updates'))
    except Exception as e:
        return f"Failed to send email: {str(e)}"

    return "Email sending failed"



#############################################download-updates###################################################

@app.route('/download_updates', methods=['GET'])
@login_required
def download_updates():
    # Retrieve selected_date and selected_shift_type from request or session
    selected_date = request.args.get('date')
    selected_shift_type = request.args.get('shift_type')

    # Query the database to get updates based on the selected date and shift type
    updates = ShiftUpdate.query.filter_by(date=selected_date, shift_type=selected_shift_type).all()

    # Generate CSV file
    csv_filename = f"shift_updates_{selected_date}_{selected_shift_type}.csv"
    csv_data = generate_csv(updates)

    # Save the CSV data to a file
    csv_filepath = app.config['CSV_DOWNLOAD_FOLDER'] + csv_filename
    with open(csv_filepath, 'w', newline='') as csv_file:
        csv_file.write(csv_data)

    # Provide the file for download
    return send_file(csv_filepath, as_attachment=True, download_name=csv_filename)

#def generate_csv(updates):
    # Create a StringIO object to store CSV data
    output = StringIO()
    writer = csv.writer(output)

    # Write CSV header
    writer.writerow([
        'date', 'shift_type', 'done_in_shift',
        'update_to_next_shift', 'alerts_handled', 'actioned_alerts',
        'manual_restarts', 'tasks', 'resolved_tasks', 'closed_tasks', 'dev_requests_calls',
        'dev_requests_pi_calls', 'dev_requests_debug_loggers', 'dev_requests_noise',
        'dev_requests_jar_replace', 'dev_requests_replicas', 'dev_requests_threads',
        'db_queries_single', 'db_queries_all_pods', 'jira_so_tickets', 'jira_ops_to_engg',
        'capacity_changes', 'activity', 'db_loads', 'follow_ups', 'shift_engineer'
    ])

    # Write data rows
    for update in updates:
        writer.writerow([
            update.date, update.shift_type, update.done_in_shift,
            update.update_to_next_shift, update.alerts_handled, update.actioned_alerts,
            update.manual_restarts, update.tasks, update.resolved_tasks, update.closed_tasks,
            update.dev_requests_calls, update.dev_requests_pi_calls, update.dev_requests_debug_loggers,
            update.dev_requests_noise, update.dev_requests_jar_replace, update.dev_requests_replicas,
            update.dev_requests_threads, update.db_queries_single, update.db_queries_all_pods,
            update.jira_so_tickets, update.jira_ops_to_engg, update.capacity_changes, update.activity,
            update.db_loads, update.follow_ups, update.shift_engineer
        ])

    return output.getvalue()

app.config['CSV_DOWNLOAD_FOLDER'] = '/root/project1/'


############################################MONTHLY##############################################################


@app.route('/monthly', methods=['GET', 'POST'])
@login_required
def monthly():
    selected_month = None  # Initialize selected_month to None.

    if request.method == 'POST':
        selected_year = request.form.get('year')
        selected_month = request.form.get('month')
        selected_updates = request.form.get('updates')

        # Check if any of the required fields is not selected
        if not selected_year or not selected_month or not selected_updates:
            flash('Please select a year, a month, and a category (P0 or P1).', 'error')
            return redirect(request.url)  # Redirect back to the form

        updates = CriticalUpdates.query.filter(
            db.extract('year', CriticalUpdates.date) == selected_year,
            db.extract('month', CriticalUpdates.date) == selected_month,
            CriticalUpdates.category == selected_updates
        ).all()

        updates = sorted(updates, key=lambda x: x.date, reverse=True)

        formatted_date = datetime(int(selected_year), int(selected_month), 1).strftime('%B %Y')
        # Render the template with the data and the selected month
        return render_template('monthly.html', updates=updates, selected_month=selected_month, year=selected_year, formatted_date=formatted_date, selected_updates=selected_updates)

    return render_template('monthly.html', updates=None, selected_month=selected_month)

def get_month_name(month_value):
    months = [
        "January", "February", "March", "April",
        "May", "June", "July", "August",
        "September", "October", "November", "December"
    ]
    return months[int(month_value) - 1]


#########################################################Tracker######################################################


@app.route('/tracker', methods=['GET', 'POST'])
@login_required
def tracker():
    if request.method == 'POST':
        date = request.form['date']
        shift = request.form['shift']
        count = int(request.form['count'])
        pod = request.form['pod']
        vm_host = request.form['vm_host']
        description = request.form['description']
        application = request.form['application']
        action_summary = request.form['action_summary']
        automation_manual = request.form['automation_manual']

        # Check if a record with the same date and shift exists in the database
        existing_record = Tracker.query.filter_by(date=date, shift=shift).first()

        if existing_record:
            count = existing_record.count  # Use the existing count

        # Insert data into the Tracker table using SQLAlchemy
        new_entry = Tracker(
            date=date,
            shift=shift,
            count=count,  # Use the existing count or the new count
            pod=pod,
            vm_host=vm_host,
            description=description,
            application=application,
            action_summary=action_summary,
            automation_manual=automation_manual,
            shift_engineer=current_user.username
        )
        db.session.add(new_entry)
        db.session.commit()

        # Create a DataFrame to store the data
        data = pd.DataFrame({
            'Date': [date],
            'Shift': [shift],
            'Count': [count],  # Use the existing count or the new count
            'Pod': [pod],
            'VM Host': [vm_host],
            'Description': [description],
            'Application': [application],
            'Action Summary': [action_summary],
            'Automation/Manual': [automation_manual],
            'Shift Engineer': [current_user.username]
        })

        # Check if the Excel file already exists
        try:
            existing_data = pd.read_excel('tracker_data.xlsx')
            data = pd.concat([existing_data, data], ignore_index=True)
        except FileNotFoundError:
            pass

        # Save the data to an Excel file
        data.to_excel('tracker_data.xlsx', index=False, engine='openpyxl')

    return render_template('tracker.html')


@app.route('/view_tracker_data', methods=['GET'])
@login_required
def view_tracker_data():
    try:
        # Retrieve tracker data from the database using SQLAlchemy
        tracker_data = Tracker.query.all()

        return render_template('view_tracker_data.html', tracker_data=tracker_data)
    except Exception as e:
        # Handle any exceptions here
        return str(e)  # You can customize the error handling as needed


@app.route('/home')
@login_required
def home():
    return render_template('home.html')

@app.route('/critical_updates')
@login_required
def critical_updates():
    return render_template('critical_updates.html')

@app.route('/c_updates')
@login_required
def c_updates():
    return render_template('c_updates.html')

@app.route('/v_updates')
@login_required
def v_updates():
    return render_template('v_updates.html')

@app.route('/t_updates')
@login_required
def t_updates():
    return render_template('t_updates.html')

@app.route('/d_updates')
@login_required
def d_updates():
    return render_template('d_updates.html')

@app.route('/ssl')
@login_required
def ssl():
    return render_template('ssl.html')


@app.route('/last_month_p0_updates', methods=['GET'])
@login_required
def last_month_p0_updates():
    try:
        one_month_ago = datetime.now() - timedelta(days=30)

        non_zero_p0_updates = CriticalUpdates.query.filter(
            CriticalUpdates.date >= one_month_ago,
            CriticalUpdates.category == "P0"
        ).all()

        non_zero_p1_updates = CriticalUpdates.query.filter(
            CriticalUpdates.date >= one_month_ago,
            CriticalUpdates.category == "P1"
        ).all()

        non_zero_p0_updates = sorted(non_zero_p0_updates, key=lambda x: x.date, reverse=True)
        non_zero_p1_updates = sorted(non_zero_p1_updates, key=lambda x: x.date, reverse=True)
        return render_template('last_month_updates.html', p0_updates=non_zero_p0_updates, p1_updates=non_zero_p1_updates)
    except Exception as e:
        return str(e)


@app.route('/last_threemonth_p0_updates', methods=['GET'])
@login_required
def last_threemonth_p0_updates():
    try:
        three_month_ago = datetime.now() - timedelta(days=90)
        non_zero_p0_updates = CriticalUpdates.query.filter(
            CriticalUpdates.date >= three_month_ago,
            CriticalUpdates.category == "P0"
        ).all()

        non_zero_p1_updates = CriticalUpdates.query.filter(
            CriticalUpdates.date >= three_month_ago,
            CriticalUpdates.category == "P1"
        ).all()
        non_zero_p0_updates = sorted(non_zero_p0_updates, key=lambda x: x.date, reverse=True)
        non_zero_p1_updates = sorted(non_zero_p1_updates, key=lambda x: x.date, reverse=True)


        return render_template('last_threemonth_updates.html', p0_updates=non_zero_p0_updates, p1_updates=non_zero_p1_updates)
    except Exception as e:
        return str(e)


@app.route('/last_sixmonth_p0_updates', methods=['GET'])
@login_required
def last_sixmonth_p0_updates():
    try:
        # Query the last one month's p0_updates
        six_months_ago = datetime.now() - timedelta(days=180)

        non_zero_p0_updates = CriticalUpdates.query.filter(
            CriticalUpdates.date >= six_months_ago,
            CriticalUpdates.category == "P0"
        ).all()

        non_zero_p1_updates = CriticalUpdates.query.filter(
            CriticalUpdates.date >= six_months_ago,
            CriticalUpdates.category == "P1"
        ).all()
        non_zero_p0_updates = sorted(non_zero_p0_updates, key=lambda x: x.date, reverse=True)
        non_zero_p1_updates = sorted(non_zero_p1_updates, key=lambda x: x.date, reverse=True)

        return render_template('last_sixmonth_updates.html', p0_updates=non_zero_p0_updates, p1_updates=non_zero_p1_updates)
    except Exception as e:
        return str(e)


# Update your Flask route to include the selected dates in the template
@app.route('/custom_time_range_updates', methods=['POST', 'GET'])
@login_required
def custom_time_range_updates():
    current_date = datetime.now()
    try:
        updates = []

        # Get the selected date range from session variables or use defaults
        from_date = session.get('from_date', current_date)
        to_date = session.get('to_date', current_date)
        selected_updates = session.get('selected_updates', 'p0_updates')  # Default value

        if request.method == 'POST':
            # Get the start and end dates from the form data
            start_date_str = request.form['fromDate']
            end_date_str = request.form['toDate']

            # Convert date strings to datetime objects
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d')

            # Check which updates are selected (P0 or P1)
            selected_updates = request.form.get('updates', 'p0_updates')

            # Store the selected radio button value in the session
            session['selected_updates'] = selected_updates

            # Store the selected dates in the session
            session['from_date'] = start_date
            session['to_date'] = end_date

            # Query ShiftUpdate objects within the custom time range based on the selected updates
            if selected_updates == 'p0_updates':
                updates = CriticalUpdates.query.filter(
                    CriticalUpdates.date >= start_date,
                    CriticalUpdates.date <= end_date,
                    CriticalUpdates.category == "P0"
                ).all()

            elif selected_updates == 'p1_updates':
                updates = CriticalUpdates.query.filter(
                    CriticalUpdates.date >= start_date,
                    CriticalUpdates.date <= end_date,
                    CriticalUpdates.category == "P1"
                ).all()

            updates = sorted(updates, key=lambda x: x.date, reverse=True)

        return render_template('custom_time_range_updates.html', updates=updates, selected_updates=selected_updates, from_date=from_date, to_date=to_date)
    except Exception as e:
        return str(e)



@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        # Get data from the form
        date = request.form['date']
        #duration = request.form['duration']
        date = request.form['date']
        hours = request.form.get('hours', '')  # Get 'hours' or empty string if not present
        minutes = request.form.get('minutes', '')  # Get 'minutes' or empty string if not present

        # Format hours and minutes with leading zeros if necessary
        formatted_hours = f"{int(hours):02d}" if hours else ''
        formatted_minutes = f"{int(minutes):02d}" if minutes else ''

        # Combine hours and minutes to create the 'duration' value
        if formatted_hours and formatted_minutes:
            duration = f"{formatted_hours}:{formatted_minutes}"
        else:
            duration = None
        category = request.form['category']
        podname = request.form['podname']
        description = request.form['description']
        service_impacted = request.form['service_impacted']
        reported_by = request.form['reported_by']

        # Ensure that the user is authenticated
        if current_user.is_authenticated:
            # Update the 'updated_by' field with the user's username
            updated_by = current_user.username

            # Create a new CriticalUpdates instance and add it to the database
            update = CriticalUpdates(
                date=date,
                duration=duration,
                category=category,
                podname=podname,
                description=description,
                service_impacted=service_impacted,
                reported_by=reported_by,
                updated_by=updated_by
            )

            db.session.add(update)
            db.session.commit()
            flash('Successfully Updated', 'success')
        else:
            flash('User is not authenticated', 'danger')
    active_menu_item = 'add-updates-link'
    return render_template('add.html', active_menu_item=active_menu_item)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/add_infra_change', methods=['GET', 'POST'])
@login_required
def add_infra_change():
    current_date = datetime.now()
    if request.method == 'POST':
        pod = request.form['pod']
        node_names = request.form.getlist('node_names')  # Retrieve the multiple node names as a list
        change_description = request.form['change_description']
        status = request.form['status']
        jira = request.form['jira']
        date_of_change = request.form['date_of_change']
        approved_by = request.form['approved_by']
        category = request.form['category']
        change_from = request.form['change_from']
        change_to = request.form['change_to']
        remarks = request.form['remarks']

        # Convert the list of node names to a comma-separated string
        node_names_str = ', '.join(node_names)

        infra_change = InfraChanges(
            pod=pod,
            node_names=node_names_str,
            change_description=change_description,
            status=status,
            jira=jira,
            date_of_change=date_of_change,
            approved_by=approved_by,
            category=category,
            change_from=change_from,
            change_to=change_to,
            remarks=remarks
        )

        db.session.add(infra_change)
        db.session.commit()

        return redirect(url_for('add_infra_change', current_date=current_date))

    return render_template('add_infra_change.html', current_date=current_date)

# Define a route to display the HTML template
@app.route('/infra_changes', methods=['GET', 'POST'])
@login_required
def infra_changes():
    if request.method == 'POST':
        pod_filter = request.form.get('pod')
        date_filter = request.form.get('date')
        node_filter = request.form.get('node')
        category_filter = request.form.get('category')

        session = Session()
        query = session.query(InfraChanges)

        # Apply filters if selected
        if pod_filter:
            query = query.filter(InfraChanges.pod == pod_filter)
        if date_filter:
            query = query.filter(InfraChanges.date_of_change == date_filter)
        if node_filter:
            query = query.filter(InfraChanges.node_names.contains(node_filter))
        if category_filter:
            query = query.filter(InfraChanges.category == category_filter)

        infra_changes = query.all()
        session.close()
    else:
        # No filters applied, get all data
        session = Session()
        infra_changes = session.query(InfraChanges).all()
        infra_changes = sorted(infra_changes, key=lambda x: x.date_of_change, reverse=True)
        session.close()

    return render_template('view_infra_changes.html', infra_changes=infra_changes)


@app.route('/add_command', methods=['GET', 'POST'])
@login_required  # Use your authentication decorator here
def add_command():
    if request.method == 'POST':
        date = datetime.now()
        category = request.form['category']
        command = request.form['command']
        usage = request.form['usage']
        created_by = current_user.username  # Assuming you have user authentication

        command_entry = CommandCenter(date=date, category=category, command=command, usage=usage, created_by=created_by)
        db.session.add(command_entry)
        db.session.commit()
        return redirect(url_for('view_commands'))

    return render_template('add_command.html')


@app.route('/command')
@login_required  # Use your authentication decorator here
def command():
    command_entries = CommandCenter.query.all()
    return render_template('command.html', command_entries=command_entries)

# Add this route to handle both GET and POST requests for filtering
@app.route('/view_commands', methods=['GET', 'POST'])
@login_required
def view_commands():
    if request.method == 'POST':
        category_filter = request.form.get('category')
        usage_filter = request.form.get('usage')

        session = Session()
        query = session.query(CommandCenter)

        # Apply filters if selected
        if category_filter:
            query = query.filter(CommandCenter.category == category_filter)

        if usage_filter:
            query = query.filter(CommandCenter.usage == usage_filter)

        commands = query.all()
        commands = sorted(commands, key=lambda x: x.date, reverse=True)

        session.close()
    else:
        # No filters applied, get all data
        session = Session()
        commands = session.query(CommandCenter).all()
        commands = sorted(commands, key=lambda x: x.date, reverse=True)
        session.close()
    # Add code to clear filters
    if 'clear_filters' in request.form:
        return redirect('/view_commands')
    return render_template('view_commands.html', commands=commands)


@app.route('/edit_command/<int:command_id>')
@login_required
def edit_command(command_id):
    command = CommandCenter.query.get(command_id)
    return render_template('edit_command.html', command=command)


@app.route('/update_command/<int:command_id>', methods=['GET','POST'])
@login_required
def update_command(command_id):
    command = CommandCenter.query.get(command_id)

    if request.method == 'POST':
        category = request.form['category']
        new_command = request.form['command']

        # Update the command with the new data
        command.category = category
        command.command = new_command

        db.session.commit()
        return redirect('/view_commands')

    return render_template('edit_command.html', command=command)



# Define the route for downloading last month's  updates
@app.route('/download_criticalupdates', methods=['GET'])
@login_required
def download_criticalupdates():
    try:
        time_frame = request.args.get('time_frame')  # Get the time frame from the request parameters
        if not time_frame:
            return "Please specify a time frame parameter."

        one_month_ago = datetime.now() - timedelta(days=30)
        three_month_ago = datetime.now() - timedelta(days=90)
        six_month_ago = datetime.now() - timedelta(days=180)

        # Fetch P0 and P1 updates for different time frames
        p0_updates, p1_updates = [], []

        if time_frame == 'last_month':
            p0_updates = CriticalUpdates.query.filter(
                CriticalUpdates.date >= one_month_ago,
                CriticalUpdates.category == "P0"
            ).all()

            p1_updates = CriticalUpdates.query.filter(
                CriticalUpdates.date >= one_month_ago,
                CriticalUpdates.category == "P1"
            ).all()
        elif time_frame == 'last_three_months':
            p0_updates = CriticalUpdates.query.filter(
                CriticalUpdates.date >= three_month_ago,
                CriticalUpdates.category == "P0"
            ).all()

            p1_updates = CriticalUpdates.query.filter(
                CriticalUpdates.date >= three_month_ago,
                CriticalUpdates.category == "P1"
            ).all()
        elif time_frame == 'last_six_months':
            p0_updates = CriticalUpdates.query.filter(
                CriticalUpdates.date >= six_month_ago,
                CriticalUpdates.category == "P0"
            ).all()

            p1_updates = CriticalUpdates.query.filter(
                CriticalUpdates.date >= six_month_ago,
                CriticalUpdates.category == "P1"
            ).all()

        if p0_updates or p1_updates:
            # Create a CSV in-memory file
            output = io.StringIO()
            csv_writer = csv.writer(output)

            # Write headers
            csv_writer.writerow(['Date', 'Category', 'Duration', 'POD Name', 'Description', 'Service Impacted', 'Reported By', 'Updated By'])

            # Write P0 data rows
            for update in p0_updates:
                csv_writer.writerow([
                    update.date.strftime('%d-%m-%Y'),
                    update.category,
                    update.duration,
                    update.podname,
                    update.description,
                    update.service_impacted,
                    update.reported_by,
                    update.updated_by
                ])

            # Write P1 data rows
            for update in p1_updates:
                csv_writer.writerow([
                    update.date.strftime('%d-%m-%Y'),
                    update.category,
                    update.duration,
                    update.podname,
                    update.description,
                    update.service_impacted,
                    update.reported_by,
                    update.updated_by
                ])

            # Create a Flask response for the CSV file
            response = Response(output.getvalue(), mimetype='text/csv')
            filename = f'{time_frame}_updates.csv'
            response.headers['Content-Disposition'] = f'attachment; filename={filename}'

            return response

        else:
            # Handle case when there are no updates
            return "No data available for the selected time frame."

    except Exception as e:
        return str(e)

@app.route('/download_monthly_updates', methods=['GET'])
@login_required
def download_monthly_updates():
    selected_year = request.args.get('year')
    selected_month = request.args.get('month')
    selected_updates = request.args.get('updates')  # Change request.args to request.form

    # Fetch all updates for the selected year and month
    updates = CriticalUpdates.query.filter(
        db.extract('year', CriticalUpdates.date) == selected_year,
        db.extract('month', CriticalUpdates.date) == selected_month,
        CriticalUpdates.category == selected_updates
    ).all()

    if updates:
        output = io.StringIO()
        csv_writer = csv.writer(output)

        # Write headers
        csv_writer.writerow(['Date', 'Category', 'Duration', 'POD Name', 'Description', 'Service Impacted', 'Reported By', 'Updated By'])

        # Write data rows for all updates
        for update in updates:
            csv_writer.writerow([
                update.date.strftime('%d-%m-%Y'),
                update.category,
                update.duration,
                update.podname,
                update.description,
                update.service_impacted,
                update.reported_by,
                update.updated_by
            ])

        response = Response(output.getvalue(), mimetype='text/csv')
        filename = f'{selected_updates}_updates.csv'
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'

        return response

    # Handle case when there are no updates
    return "No data available for the selected month and year."


##----------debug_logs-------------------------#
@app.route('/debug')
def debug():
    debug_logs = DebugLog.query.all()
    return render_template('debug.html', debug_logs=debug_logs)


@app.route('/add_debug_log', methods=['GET','POST'])
def add_debug_log():
    date = request.form['date']
    pod_name = request.form['pod_name']
    application = request.form['application']
    node_names = request.form['node_names']
    jira_id = request.form['jira_id']
    jira_status = request.form['jira_status']
    done_by = current_user.username  # Replace with actual user authentication

    debug_log = DebugLog(date=date, pod_name=pod_name, application=application, node_names=node_names,
                        jira_id=jira_id, jira_status=jira_status, done_by=done_by)

    db.session.add(debug_log)
    db.session.commit()
    return redirect(url_for('view_debug_logs'))



@app.route('/view_debug_logs', methods=['GET'])
def view_debug_logs():
    debug_logs = DebugLog.query.all()
    return render_template('view_debug_logs.html', debug_logs=debug_logs)

    return redirect(url_for('view_debug_logs'))


@app.route('/update_jira_status/<int:id>', methods=['POST'])
def update_jira_status(id):
    if request.method == 'POST':
        debug_log = DebugLog.query.get(id)
        current_status = debug_log.jira_status
        new_status = request.form['jira_status']

        # Check if the current status is 'Closed'
        if current_status == 'Closed':
            flash("Status is already Closed and cannot be changed.", 'error')
        else:
            # Update the status
            debug_log.jira_status = new_status

            # If the new status is 'Closed', set the closed_date
            if new_status == 'Closed':
                debug_log.closed_date = datetime.now().strftime('%Y-%m-%d')

            db.session.commit()

    return redirect(url_for('view_debug_logs'))


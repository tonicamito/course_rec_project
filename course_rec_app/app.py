import secrets
import shutil
import string
import pandas as pd
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
from flask import Flask, abort, make_response, request, jsonify, send_from_directory 
import ast
import sqlite3
import json
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, UTC
from functools import wraps
from flask import Flask,render_template,url_for ,redirect,send_file
from sqlite3 import DatabaseError
from flask import session,Response
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
from email.mime.text import MIMEText
import os
import zipfile
import io
import re
from flask_caching import Cache


app = Flask(__name__, static_folder='static', template_folder='templates')
from flask_cors import CORS
CORS(app, supports_credentials=True)

DATABASE="courseDB.sqlite"

app.config['SECRET_KEY'] = 'your-secret-key-here'  
app.config['JWT_ALGORITHM'] = 'HS256'  
app.config['JWT_EXPIRATION'] = timedelta(hours=1)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'courseadvisor00@gmail.com'
app.config['MAIL_PASSWORD'] = 'dehknqogbgcwwfvt'
app.config['VERIFICATION_EXPIRE_HOURS'] = 24
cache = Cache(config={'CACHE_TYPE': 'SimpleCache'})
cache.init_app(app)
from dotenv import load_dotenv
load_dotenv()


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Return rows as dictionaries
    return conn

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute(
        '''SELECT user_id, firstName, lastName, username, email, 
            password_hash, educationLevel, is_admin, is_verified, password_reset_required
            FROM users WHERE username = ?''' ,
        (username,)
    ).fetchone()
    conn.close()
    return user

print("Current working directory:", os.getcwd())

# Initialize database tables
def init_db():
    conn = get_db_connection()
    with app.open_resource('schema.sql', mode='r') as f:
        conn.cursor().executescript(f.read())
    conn.commit()
    conn.close()


def load_majors_data(filepath):
    df = pd.read_csv(filepath)
    
    # Convert string representations of dictionaries to actual dictionaries.
    dict_columns = ['required_subjects', 'interests', 'skills', 
                    'learning_preferences', 'personality_traits', 'career_goals']
    
    for col in dict_columns:
        if col in df.columns:
            df[col] = df[col].apply(lambda x: ast.literal_eval(x) if pd.notnull(x) else {})
        else:
            df[col] = [{}] * len(df)
    
    # Create a feature vector for each major.
    df['feature_vector'] = df.apply(create_feature_vector, axis=1)
    
    return df

def get_weights_from_db():
    conn = get_db_connection()
    weights = conn.execute(
        'SELECT * FROM recommendation_weights ORDER BY created_at DESC LIMIT 1'
    ).fetchone()
    conn.close()
    
    if weights:
        return {
            'required_subjects': weights['required_subjects'],
            'interests': weights['interests'],
            'learning_preferences': weights['learning_preferences'],
            'personality_traits': weights['personality_traits'],
            'career_goals': weights['career_goals']
        }
    else:
        # Return default weights if none exist in DB
        return {
            'required_subjects': 0.4,
            'interests': 0.2,
            'learning_preferences': 0.15,
            'personality_traits': 0.15,
            'career_goals': 0.1
        }
    
def create_feature_vector(row):
    features = []
    weights = get_weights_from_db()
    #  expected keys for each dictionary column.
    
    expected_keys = {
        'required_subjects': {
        'Mathematics', 'English', 'Kiswahili',
        'Biology', 'Business', 'Computer studies', 'French',
        'Chemistry', 'Physics', 'History', 'Geography', 
        'Religious studies', 'Agriculture'
        },
        'interests': {
        'critical_thinking', 'numbers_data', 'social_problems',
        'teaching_helping', 'different_cultures', 'environmental_issues',
        'global_politics', 'interacting_with_people', 'religious_spiritual',
        'scientific_research', 'organizing_information'
        },
        'learning_preferences': {
            'working_preference', 'collaboration_preference', 'problem_solving'
        },
        'personality_traits': {
            'problem_approach', 'public_speaking', 'high_pressure', 'helping_others'
        },
        'career_goals': {
            'career_values', 'work_sector', 'further_studies'
        }
    }

    for section, keys in expected_keys.items():
        # Get weight for this section from database
        section_weight = weights.get(section, 0.1)  # Defaults to 0.1 if not found
        
        values = row.get(section, {})
        
        for key in keys:
            val = values.get(key, 0)
            # If the value is a list/tuple, use the first element
            if isinstance(val, (list, tuple)):
                try:
                    val = float(val[0])
                except Exception:
                    val = 0
            else:
                try:
                    val = float(val)
                except Exception:
                    val = 0
            features.append(val * section_weight)
    
    return np.array(features)

# Process the user input from the questionnaire and create a feature vector.
def process_user_input(user_data):
    def get_numeric_value(val, default=1):
        # If the value is a list, use the first element
        if isinstance(val, list): 
            if len(val) > 0:
                val = val[0]
            else:
                return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    feature_vector = []
    
    
    grade_mapping = {
        'A': 1.0, 'A-': 0.9, 'B+': 0.8, 'B': 0.7, 'B-': 0.6,
        'C+': 0.5, 'C': 0.4, 'C-': 0.3, 'D+': 0.2, 'D': 0.1,
        'D-': 0.0, 'E': 0.0
    }
    subjects = [
        'Mathematics', 'English', 'Kiswahili', 'Biology', 'Business',
        'Computer studies', 'French', 'Chemistry', 'Physics', 'History',
        'Geography', 'Religious studies', 'Agriculture'
    ]
    subject_grades = user_data.get('subject_grades', {})
    # If subject_grades comes as a list of objects, convert it to a dict.
    if isinstance(subject_grades, list):
        temp = {}
        for item in subject_grades:
            subject = item.get('subject', '').strip()
            grade = item.get('grade', 'E').strip()
            if subject:
                temp[subject] = grade
        subject_grades = temp

    for subject in subjects:
        grade = subject_grades.get(subject, 'E')
        feature_vector.append(grade_mapping.get(grade.upper(), 0))
    
   
    interests = [
        'critical_thinking', 'numbers_data', 'social_problems',
        'teaching_helping', 'different_cultures', 'environmental_issues',
        'global_politics', 'interacting_with_people', 'religious_spiritual',
        'scientific_research', 'organizing_information'
    ]
    for key in interests:
        value = get_numeric_value(user_data.get(key, 1))
        norm = (value - 1) / 4  # normalize from 0 to 1
        feature_vector.append(norm)
    
    
    learning_preferences = ['working_preference', 'collaboration_preference', 'problem_solving']
    for key in learning_preferences:
        value = get_numeric_value(user_data.get(key, 1))
        norm = (value - 1) / 4
        feature_vector.append(norm)
    
    
    personality_traits = ['problem_approach', 'public_speaking', 'high_pressure', 'helping_others']
    for key in personality_traits:
        value = get_numeric_value(user_data.get(key, 1))
        norm = (value - 1) / 4
        feature_vector.append(norm)
    
    
    career_goals = ['career_values', 'work_sector', 'further_studies']
    for key in career_goals:
        value = get_numeric_value(user_data.get(key, 1))
        norm = (value - 1) / 4
        feature_vector.append(norm)
    
    return np.array(feature_vector)



# Recommendation engine.
class MajorRecommender:
    def __init__(self, data_path):
        self.weights = get_weights_from_db()
        self.grade_mapping = {
            'A': 1.0, 'A-': 0.9, 'B+': 0.8, 'B': 0.7, 'B-': 0.6,
            'C+': 0.5, 'C': 0.4, 'C-': 0.3, 'D+': 0.2, 'D': 0.1, 
            'D-': 0.0, 'E': 0.0
        }
        self.df = self._validate_and_load_data(data_path)
        self.feature_matrix = np.vstack(self.df['feature_vector'].values)

    def _validate_and_load_data(self, data_path):
        df = load_majors_data(data_path)
        
        required_columns = ['course_name', 'description', 'minimum_grade', 'feature_vector']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Missing required column in CSV: {col}")
        
        valid_grades = set(self.grade_mapping.keys())
        df['grade_valid'] = df['minimum_grade'].str.upper().isin(valid_grades)
        if df['grade_valid'].sum() != len(df):
            invalid = df[~df['grade_valid']]['minimum_grade'].unique()
            raise ValueError(f"Invalid minimum grades found: {invalid}")
        
        return df



    def get_recommendations(self, user_data, top_n=3, min_similarity=0.2):
    # Generate the user vector
        try:
            user_vector = process_user_input(user_data).reshape(1, -1)
        except Exception as e:
            raise ValueError(f"Error processing user input: {str(e)}")
        
        # Calculate similarities between the user vector and all major feature vectors
        similarities = cosine_similarity(user_vector, self.feature_matrix)[0]
        
        # Get user's grade and its numeric value
        user_grade = user_data.get('kcse_grade', 'E').upper()
        try:
            user_grade_value = self.grade_mapping[user_grade]
        except KeyError:
            user_grade_value = 0.0  
        
        # Build candidates list based on similarity and grade criteria
        candidates = []
        for idx, similarity in enumerate(similarities):
            major = self.df.iloc[idx]
            # Calculate match percentage
            match_percent = max(0, (similarity + 1) / 2 * 100)
            # Check if the user's grade meets the requirement for this major
            major_grade = major['minimum_grade'].upper()
            grade_met = user_grade_value >= self.grade_mapping.get(major_grade, 0)
            if grade_met and match_percent >= min_similarity:
                candidates.append({
                    'index': idx,
                    'similarity': similarity,
                    'match_percent': match_percent,
                    'course_name': major['course_name'],
                    'description': major['description']
                })
        # Sort candidates by match_percent descending
        candidates.sort(key=lambda x: x['match_percent'], reverse=True)
        
        # Fallback: if there are insufficient candidates, use fallback recommendations.
        if len(candidates) < top_n:
            app.logger.warning(f"Only {len(candidates)} candidates met criteria. Expanding search.")
            fallback_candidates = self._fallback_recommendations(user_grade_value, top_n)
            # Ensure every fallback recommendation has a 'match_percent' key
            for rec in fallback_candidates:
                if 'match_percent' not in rec:
                    rec['match_percent'] = 0
            candidates = fallback_candidates
        
        return candidates[:top_n]


    def _fallback_recommendations(self, user_grade_value, top_n):

            # Create a new column with vector norms
        df_filtered = self.df[self.df['minimum_grade'].apply(
                lambda g: user_grade_value >= self.grade_mapping.get(g.upper(), 0))
        ].copy()
            
            # Calculate vector norms
        df_filtered['vector_norm'] = df_filtered['feature_vector'].apply(np.linalg.norm)
            
            # Sort by vector norm
        return df_filtered.sort_values(by='vector_norm', ascending=False).head(top_n).to_dict('records')

    def get_course_id(self, course_name):
        """Safe course ID lookup with error handling"""
        conn = get_db_connection()
        try:
            course = conn.execute(
                'SELECT course_id FROM courses WHERE course_name = ?',
                (course_name,)
            ).fetchone()
            return course['course_id'] if course else None
        except Exception as e:
            raise DatabaseError(f"Course lookup failed: {str(e)}")
        finally:
            conn.close()
    
    def update_weights(self, new_weights):
        self.weights = new_weights  
        self.df['feature_vector'] = self.df.apply(
            lambda row: create_feature_vector(row), 
            axis=1
        )
        self.feature_matrix = np.vstack(self.df['feature_vector'].values)

# Initialize the recommender.
recommender = MajorRecommender('newcuea-majors-mapping.csv')

# Helper functions for database operations
def create_user(firstName,lastName,username, email, password,educationLevel):
    conn = get_db_connection()
    try:
        # Generate password hash
        hashed_pw = generate_password_hash(password)
        
        conn.execute('''
            INSERT INTO users (firstName,lastName,username, email, password_hash,educationLevel)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (firstName,lastName,username, email, hashed_pw,educationLevel))
        conn.commit()
        return conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def create_questionnaire_response(user_id, response_data):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO questionnaire_responses (user_id, response_data)
            VALUES (?, ?)
        ''', (user_id, json.dumps(response_data)))
        conn.commit()
        return conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    finally:
        conn.close()

def create_recommendation(user_id, course_id, match_percentage):
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO recommendations (user_id, course_id, match_percentage)
            VALUES (?, ?, ?)
        ''', (user_id, course_id, match_percentage))
        conn.commit()
    finally:
        conn.close()

def update_course(course_id, course_data):
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE courses 
            SET course_name = ?, description = ?, required_subjects = ?, 
                minimum_grade = ?, program_type = ?
            WHERE course_id = ?
            ''', (
                course_data['course_name'],
                course_data['description'],
                json.dumps(course_data['required_subjects']),
                course_data['minimum_grade'],
                course_data['program_type'],
                course_id
            ))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        return False
    finally:
        conn.close()

#creating jwt validation decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Try to get token from Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        # If not found in header, try cookie
        if not token:
            token = request.cookies.get('auth_token')

        #  Fallback to query parameter (for testing/debug)
        if not token:
            token = request.args.get('token')

        if not token:
            return jsonify({'error': 'Authentication required'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[app.config['JWT_ALGORITHM']])
            current_user = {
                'user_id': data['user_id'],
                'username': data['username'],
                'email': data['email'],
                'is_admin': data['is_admin'],
                'education_level': data['education_level']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Session expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid authentication token'}), 401
        except Exception as e:
            app.logger.error(f"Token validation error: {str(e)}")
            return jsonify({'error': 'Authentication failed'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


def log_admin_action(action, target_type=None, target_id_param=None):
    def decorator(f):
        @wraps(f)
        def wrapped(current_user, *args, **kwargs):
            # If target_id_param is a string, look it up in kwargs
            if isinstance(target_id_param, str):
                tid = kwargs.get(target_id_param)
            else:
                tid = target_id_param
            conn = get_db_connection()
            conn.execute(
                '''INSERT INTO admin_logs (user_id, action, target_type, target_id)
                   VALUES (?, ?, ?, ?)''',
                (current_user['user_id'], action, target_type, tid)
            )
            conn.commit()
            conn.close()
            return f(current_user, *args, **kwargs)
        return wrapped
    return decorator


def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification-salt')

def send_verification_email(user_email, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    
    msg = MIMEText(f'''Please verify your email by clicking the link below:
{verification_url}

This link will expire in {app.config['VERIFICATION_EXPIRE_HOURS']} hours.''')
    
    msg['Subject'] = 'Verify Your Email Address'
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = user_email

    server = None
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
    finally:
        if server:
            try:
              
                server.close()
            except Exception as quit_error:
                app.logger.error(f"Error closing SMTP connection: {str(quit_error)}")

def is_password_strong(password):
    if len(password) < 8:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_lower and has_upper and has_digit and has_special

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


@app.route('/recommend', methods=['POST'])
@token_required
def recommend(current_user):
    try:
        user_data = request.json
        grade_mapping = {'A': 1.0, 'A-': 0.9, 'B+': 0.8, 'B': 0.7, 'B-': 0.6,
                         'C+': 0.5, 'C': 0.4, 'C-': 0.3, 'D+': 0.2, 'D': 0.1, 'D-': 0.0}
        
        # Process subject grades
        if isinstance(user_data.get('subject_grades'), list):
            subject_grades = {}
            for item in user_data['subject_grades']:
                subject = item.get('subject', '').strip()
                grade = item.get('grade', 'E').strip().upper()
                if not subject:
                    continue
                subject_grades[subject] = grade if grade in grade_mapping else 'E'
            user_data['subject_grades'] = subject_grades
        else:
            user_data['subject_grades'] = {
                k: v.upper() if v.upper() in grade_mapping else 'E'
                for k, v in user_data['subject_grades'].items()
            }

        # Validate required fields
        required_fields = ['kcse_grade', 'best_subjects', 'subject_grades']
        for field in required_fields:
            if field not in user_data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Get recommendations
        recommendations = recommender.get_recommendations(user_data)
        app.logger.debug(f"Generated recommendations: {recommendations}")

        # Store response in database
        response_id = create_questionnaire_response(
            current_user['user_id'],
            user_data
        )

        # Process and store recommendations
        stored_recs = []
        for rec in recommendations:
            course_id = recommender.get_course_id(rec['course_name'])
            if course_id:
                create_recommendation(
                    user_id=current_user['user_id'],
                    course_id=course_id,
                    match_percentage=rec['match_percent']
                )
                stored_recs.append({
                    'course_name': rec['course_name'],
                    'match_percent': rec['match_percent'],
                    'description': rec.get('description', '')
                })

        # Store recommendations in session for results page
        session['recommendations'] = stored_recs
        session.modified = True

        return jsonify({
            'status': 'success',
            'recommendations': stored_recs,
            'questionnaire_response_id': response_id
        })
    
    except Exception as e:
        app.logger.error(f'Recommendation error: {str(e)}')
        return jsonify({'error': str(e)}), 500


@app.route('/index')
@token_required
def index(current_user):
    return render_template('index.html', user=current_user)

@app.route('/login', methods=['GET', 'POST','HEAD'])
def serve_login():
    try:

        if request.method == 'GET':
            return render_template('login.html')
        
        if request.method == 'HEAD':
            return '', 200  # Respond with empty body

        # Only accept JSON
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid request, no JSON received'}), 400

        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({'error': 'Missing username or password'}), 400

        user = get_user_by_username(username)
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not user['is_verified']:
            return jsonify({'error': 'Please verify your email before logging in'}), 403

        # If user needs a forced reset…
        if user['password_reset_required']:
            return jsonify({
                'password_reset_required': True,
                'user_id': user['user_id']
            }), 403

        # Build Json web token
        payload = {
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'is_admin': bool(user['is_admin']),
            'education_level': user['educationLevel'],
            'exp': datetime.utcnow() + app.config['JWT_EXPIRATION'],
            'is_verified':bool(user['is_verified']),
            'password_reset_required': bool(user['password_reset_required'])
        }
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

        resp = jsonify({
        'token': token,
        'password_reset_required': bool(user['password_reset_required']),  
        'user_info': {
            'user_id': user['user_id'],
            'username': user['username'],
            'email': user['email'],
            'education_level': user['educationLevel'],
            'is_admin': bool(user['is_admin']),
            'password_reset_required': bool(user['password_reset_required'])  
        }
        })
        

        # Set the cookie
        resp.set_cookie(
            'auth_token', token,
            httponly=False,
            secure=False,  
            samesite='Lax',
            max_age=int(app.config['JWT_EXPIRATION'].total_seconds()),
            path='/'
        )

        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET last_login = ? WHERE user_id = ?', 
            (datetime.now(UTC).isoformat(), user['user_id'])
        )
        conn.commit()
        conn.close()
        return resp, 200

    except Exception as e:
        app.logger.exception("Login error")
        return jsonify({'error': 'Internal server error'}), 500
    
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'error': 'Email is required'}), 400

    email = data['email']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'message': 'If the email exists, password reset instructions will be sent'}), 200
    
    # Generate reset token
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    token = serializer.dumps(user['email'], salt='password-reset')

    # Store token and expiration
    expiration = datetime.now(UTC) + timedelta(hours=1)
    expiration_str = expiration.isoformat()
    
    conn.execute('''
        UPDATE users 
        SET reset_token = ?, reset_token_expiration = ?
        WHERE user_id = ?
    ''', (token, expiration_str, user['user_id']))
    conn.commit()
    conn.close()

    # Create reset link
    reset_url = url_for('render_reset_password_page', _external=True, token=token)

    # Send email
    msg = MIMEText(f'''Click to reset your password: {reset_url}\n\nLink expires in 1 hour.''')
    msg['Subject'] = 'Password Reset Request'
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = email

    server = None
    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        app.logger.info(f"Password reset email sent to: {email}")
        return jsonify({'message': 'Password reset email sent'}), 200
    except Exception as e:
        app.logger.error(f"Error sending email: {str(e)}")
        return jsonify({'error': 'Failed to send reset email'}), 500
    finally:
        if server:
            try:
                # Changed from server.quit() to server.close()
                server.close()
            except Exception as quit_error:
                app.logger.error(f"Error closing SMTP connection: {str(quit_error)}")

    
@app.route('/forgot-password', methods=['GET'])
def forgot_password_page():
    return render_template('forgot-password.html')

@app.route('/api/verify-reset-token', methods=['GET'])
def verify_reset_token():
    token = request.args.get('token')
    if not token:
        return jsonify({'valid': False, 'error': 'Token required'}), 400
    
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except Exception as e:
        app.logger.error(f"Token validation error: {str(e)}")
        return jsonify({'valid': False, 'error': 'Invalid/expired token'}), 400
    
    conn = get_db_connection()
    current_utc = datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')

    
    user = conn.execute('''
        SELECT * FROM users 
        WHERE email = ?
        AND reset_token = ?
        AND reset_token_expiration > ?
    ''', (email, token, current_utc)).fetchone()
    
    conn.close()
    
    if user:
        # Additional check for token expiration
        expiration_str = user['reset_token_expiration']
        # Parse ISO format datetime
        expiration_time = datetime.fromisoformat(expiration_str)
        if datetime.now(UTC) > expiration_time:
            return jsonify({'valid': False, 'error': 'Token has expired'}), 400
            
        return jsonify({
            'valid': True,
            'expiration': user['reset_token_expiration']  # Include expiration time in response
        }), 200
    else:
        app.logger.warning(f"Token valid but user lookup failed for email: {email}")
        return jsonify({'valid': False, 'error': 'User not found or token expired'}), 400

@app.route('/reset-password')  # Remove <token> from path
def render_reset_password_page():
    token = request.args.get('token')  # Get token from query string
    if not token:
        abort(400, description="Missing token parameter")
    return render_template('reset-password.html', token=token)

@app.route('/api/reset-password', methods=['POST'])  # No token in path
def reset_password_with_token():
    data = request.get_json()

    token = request.args.get('token')  # Get token from query string
    if not token:
        return jsonify({'error': 'Token is required'}), 400
    if not data or 'password' not in data:
        return jsonify({'error': 'Password is required'}), 400

    # Verify token using itsdangerous
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        app.logger.warning("Token expired")
        return jsonify({'error': 'Token has expired'}), 400
    except BadSignature:
        app.logger.warning("Invalid token signature")
        return jsonify({'error': 'Invalid token'}), 400
    except Exception as e:
        app.logger.error(f"Unexpected token error: {str(e)}")
        return jsonify({'error': 'Token processing error'}), 400

    conn = get_db_connection()
    user = conn.execute('''
        SELECT * FROM users 
        WHERE email = ? AND reset_token = ?
    ''', (email, token)).fetchone()

    if not user:
        conn.close()
        return jsonify({'error': 'User not found or token invalid'}), 400

    # Check expiration manually from DB
    expiration_str = user['reset_token_expiration']
    app.logger.info(f"Raw expiration_str from DB: {expiration_str}")

    try:
        expiration_time = datetime.fromisoformat(expiration_str).replace(tzinfo=UTC)
        now_utc = datetime.now(UTC)
        app.logger.info(f"NOW: {now_utc.isoformat()}")
        app.logger.info(f"EXPIRATION: {expiration_time.isoformat()}")

        if now_utc > expiration_time:
            conn.close()
            return jsonify({'error': 'Token has expired'}), 400
    except Exception as e:
        conn.close()
        app.logger.error(f"Error parsing expiration: {str(e)}")
        return jsonify({'error': 'Invalid expiration format'}), 400

    # Validate password strength
    if len(data['password']) < 8 or not is_password_strong(data['password']):
        conn.close()
        return jsonify({'error': 'Password too weak or too short'}), 400

    # Update password in DB
    hashed_pw = generate_password_hash(data['password'])
    conn.execute('''
        UPDATE users 
        SET password_hash = ?, 
            reset_token = NULL,
            reset_token_expiration = NULL,
            password_reset_required = 0
        WHERE user_id = ?
    ''', (hashed_pw, user['user_id']))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Password reset successfully'}), 200

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def serve_register():
    if request.method == 'POST':
        try:
            data = request.get_json()
            required_fields = ['firstName', 'lastName', 'username', 'email', 'password', 'educationLevel']

            for field in required_fields:
                if field not in data:
                    return jsonify({'error': f'Missing {field}'}), 400

            if data['password'] != data.get('confirmPassword'):
                return jsonify({'error': 'Passwords do not match'}), 400

            user_id = create_user(
                firstName=data['firstName'],
                lastName=data['lastName'],
                username=data['username'],
                email=data['email'],
                password=data['password'],  
                educationLevel=data['educationLevel']
            )

            if not user_id:
                return jsonify({'error': 'Username or email already exists'}), 409
            
             # Generate verification token
            conn = get_db_connection()
            try:
                verification_token = generate_verification_token(data['email'])
                expiration = datetime.utcnow() + timedelta(hours=app.config['VERIFICATION_EXPIRE_HOURS'])
                
                conn.execute('''UPDATE users SET 
                    verification_token = ?,
                    token_expiration = ?
                    WHERE user_id = ?''',
                    (verification_token, expiration, user_id))
                conn.commit()
                
                send_verification_email(data['email'], verification_token)
            except Exception as e:
                return jsonify({'error': str(e)}), 500
            finally:
                conn.close()

            return jsonify({'message': 'Registration successful! Please check your email to verify your account.'}), 201


        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'}), 409
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return render_template('register.html')

# Helper function to create user
def create_user(firstName, lastName, username, email, password, educationLevel):
    conn = get_db_connection()
    try:
        hashed_pw = generate_password_hash(password)  

        conn.execute('''
            INSERT INTO users (firstName, lastName, username, email, password_hash, educationLevel)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (firstName, lastName, username, email, hashed_pw, educationLevel))
        conn.commit()
        return conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()




@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        email = serializer.loads(
            token,
            salt='email-verification-salt',
            max_age=app.config['VERIFICATION_EXPIRE_HOURS'] * 3600
        )
    except:
        return jsonify({'error': 'Invalid or expired verification link'}), 400

    conn = get_db_connection()
    user = conn.execute('''SELECT * FROM users 
                        WHERE email = ? AND verification_token = ? 
                        AND token_expiration > datetime('now')''',
                      (email, token)).fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid verification request'}), 400

    conn.execute('''UPDATE users SET 
                  is_verified = 1,
                  verification_token = NULL,
                  token_expiration = NULL
                  WHERE user_id = ?''',
               (user['user_id'],))
    conn.commit()
    conn.close()

    return redirect(url_for('serve_login'))

@app.route('/resend-verification', methods=['POST'])
def resend_verification():
    data = request.get_json()
    if 'email' not in data:
        return jsonify({'error': 'Email required'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (data['email'],)).fetchone()
    if not user:
        return jsonify({'error': 'Email not found'}), 404
    if user['is_verified']:
        return jsonify({'error': 'Email already verified'}), 400

    # Generate new token
    verification_token = generate_verification_token(data['email'])
    expiration = datetime.now(UTC) + timedelta(hours=app.config['VERIFICATION_EXPIRE_HOURS'])
    
    conn.execute('''UPDATE users SET 
                  verification_token = ?,
                  token_expiration = ?
                  WHERE user_id = ?''',
               (verification_token, expiration, user['user_id']))
    conn.commit()
    conn.close()

    send_verification_email(data['email'], verification_token)
    return jsonify({'message': 'Verification email resent successfully'}), 200

@app.route('/logout')
def logout():
    response = redirect(url_for('serve_login'))
    response.delete_cookie('auth_token', path='/')  # Add path='/'
    return response



@app.route("/questionnaire", methods=["GET", "POST"])
@token_required
def questionnaire(current_user):
    """Handle questionnaire display and submission"""
    if request.method == "HEAD":
        return "", 200
    if request.method == "GET":
        return render_template("Questionnaire.html",user=current_user)

    if request.method == "POST":
        try:
            user_data = request.get_json(silent=True)  
            if not user_data:
                return jsonify({"error": "Invalid or missing JSON data"}), 400  # it Returns 400 Bad Request

            recommendations = recommender.get_recommendations(user_data)

            session["recommendations"] = recommendations  # Store recommendations in session

            return jsonify({"redirect": url_for("results")}), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500  # Return 500 Internal Server Error

    return jsonify({"error": "Unexpected request method"}), 405  # Return 405 for other methods


@app.route('/results')
@token_required
def results(current_user):
    recommendations = session.get('recommendations')
    if not recommendations:
        app.logger.warning("No recommendations found in session")
        return redirect(url_for('questionnaire'))
    
    app.logger.debug(f"Rendering results with: {recommendations}")
    return render_template('results.html', 
                         recommendations=recommendations, 
                         user=current_user)



def create_questionnaire_response(user_id, response_data):
    """Store raw questionnaire response"""
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO questionnaire_responses 
            (user_id, response_data)
            VALUES (?, ?)
        ''', (user_id, json.dumps(response_data)))
        conn.commit()
        return conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    finally:
        conn.close()

def create_recommendation(user_id, course_id, match_percentage):
    """Store individual recommendation"""
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO recommendations 
            (user_id, course_id, match_percentage)
            VALUES (?, ?, ?)
        ''', (user_id, course_id, match_percentage))
        conn.commit()
    finally:
        conn.close()

@app.route('/refresh', methods=['POST'])
@token_required
def refresh_token(current_user):
    new_token = jwt.encode({
        'user_id': current_user['user_id'],
        'exp': datetime.utcnow() + app.config['JWT_EXPIRATION']
    }, app.config['SECRET_KEY'], algorithm=app.config['JWT_ALGORITHM'])

    return jsonify({'token': new_token})



@app.route('/admin')
@token_required
def admin_dashboard(current_user):
    if not current_user['is_admin']:
        abort(403)
    return render_template('admin.html', user=current_user)



@app.route('/api/admin/users', methods=['GET', 'POST'], strict_slashes=False)
@token_required
def users_handler(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    if request.method == 'GET':
        conn = get_db_connection()
        try:
            #  Add filtering parameters here
            username_filter = request.args.get('username')
            email_filter = request.args.get('email')
            role_filter = request.args.get('role')
            verified_filter = request.args.get('verified')
            
            query = '''
                SELECT user_id, firstName, lastName, username, email, educationLevel, 
                    is_admin, is_verified, last_login
                FROM users
                WHERE 1=1
            '''
            params = []
            
            if username_filter:
                query += " AND username LIKE ?"
                params.append(f'%{username_filter}%')
            
            if email_filter:
                query += " AND email LIKE ?"
                params.append(f'%{email_filter}%')
            
            if role_filter:
                query += " AND is_admin = ?"
                params.append(1 if role_filter == 'admin' else 0)
            
            if verified_filter:
                query += " AND is_verified = ?"
                params.append(1 if verified_filter == 'verified' else 0)
            
            users = conn.execute(query, tuple(params)).fetchall()
            users_list = [dict(user) for user in users]
            return jsonify(users_list)
        except Exception as e:
            app.logger.error(f"Error getting users: {str(e)}")
            return jsonify({'error': 'Internal server error'}), 500
        finally:
            conn.close()

    elif request.method == 'POST':
        data = request.get_json()
        required_fields = ['firstName', 'lastName', 'username', 'email', 'educationLevel', 'is_admin']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400
        
        # Handle password logic
        password = data.get('password')
        if password:
            if (len(password) < 10 or 
                not re.search(r'\d', password) or 
                not re.search(r'[A-Z]', password) or
                not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
                return jsonify({'error': 'Password must be 10+ chars with uppercase, number and special character'}), 400
            hashed_pw = generate_password_hash(password)
            reset_required = 0  # No reset needed
        else:
            hashed_pw = generate_password_hash('TempPassword123!')
            reset_required = 1  # Force reset

        try:
            conn = get_db_connection()
            verification_token = None
            expiration = None
            if data.get('sendVerification'):
                verification_token = generate_verification_token(data['email'])
                expiration = datetime.utcnow() + timedelta(hours=app.config['VERIFICATION_EXPIRE_HOURS'])
            
            conn.execute('''
                INSERT INTO users (
                    firstName, lastName, username, email, password_hash, 
                    educationLevel, is_admin, password_reset_required,
                    is_verified, verification_token, token_expiration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
            ''', (
                data['firstName'],
                data['lastName'],
                data['username'],
                data['email'],
                hashed_pw,
                data['educationLevel'],
                1 if data['is_admin'] else 0,
                reset_required,
                0 if data.get('sendVerification') else 1,  # Marks unverified if sending verification
                verification_token,
                expiration
            ))
            user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
            conn.commit()
            
            # Send verification email if requested
            if data.get('sendVerification'):
                try:
                    send_verification_email(data['email'], verification_token)
                except Exception as e:
                    app.logger.error(f"Failed to send verification email: {str(e)}")
            
            return jsonify({'status': 'User created'}), 201
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists'}), 409
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()
    else:
            return jsonify({'error': 'Method not allowed'}), 405

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.get_json()
    conn = get_db_connection()
    try:
        # Handles password update
        update_password = ''
        if 'password' in data and data['password']:
             
            if not is_password_strong(data['password']):
                return jsonify({'error': 'Password must be 8+ chars with uppercase, lowercase, number and special character'}), 400
            hashed_pw = generate_password_hash(data['password'])
            update_password = 'password_hash = ?,'
            params = [hashed_pw]
        else:
            params = []
        
        # Generates new verification token if requested
        verification_update = ''
        if data.get('resendVerification'):
            verification_token = generate_verification_token(data['email'])
            expiration = datetime.utcnow() + timedelta(hours=app.config['VERIFICATION_EXPIRE_HOURS'])
            verification_update = 'verification_token = ?, token_expiration = ?, is_verified = 0,'
            params.extend([verification_token, expiration])
            try:
                send_verification_email(data['email'], verification_token)
            except Exception as e:
                app.logger.error(f"Failed to send verification email: {str(e)}")
        
        # Build query
        query = f'''
            UPDATE users SET
            {update_password}
            {verification_update}
            firstName = ?, lastName = ?, username = ?,
            email = ?, educationLevel = ?, is_admin = ?
            WHERE user_id = ?
        '''
        params.extend([
            data['firstName'],
            data['lastName'],
            data['username'],
            data['email'],
            data['educationLevel'],
            1 if data.get('is_admin', False) else 0,
            user_id
        ])
        
        conn.execute(query, tuple(params))
        conn.commit()
        return jsonify({'message': 'User updated successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
        
@app.route('/api/admin/users/check-username', methods=['GET'])
@token_required
def check_username(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    username = request.args.get('username')
    exclude_id = request.args.get('excludeId', type=int)
    
    if not username:
        return jsonify({'error': 'Username is required'}), 400

    conn = get_db_connection()
    query = 'SELECT user_id FROM users WHERE username = ?'
    params = [username]
    
    if exclude_id:
        query += ' AND user_id != ?'
        params.append(exclude_id)
        
    user = conn.execute(query, tuple(params)).fetchone()
    conn.close()
    
    return jsonify({'isTaken': user is not None})



@app.route('/api/admin/courses', methods=['POST'])
@token_required
def add_course(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    data = request.get_json()
    
    for field in ['course_name', 'description', 'required_subjects', 'minimum_grade', 'career_paths']:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO courses
              (course_name, description, required_subjects, minimum_grade, program_type, career_paths)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            data['course_name'],
            data['description'],
            json.dumps(data['required_subjects']),
            data['minimum_grade'],
            data.get('program_type', 'undergraduate'),
            json.dumps(data['career_paths'])  
        ))
        conn.commit()
        return jsonify({'status': 'Course added'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        conn.close()

@app.route('/api/admin/courses', methods=['GET'])
@token_required
def get_courses(current_user):
    conn = get_db_connection()
    courses = conn.execute('SELECT * FROM courses').fetchall()
    conn.close()
    return jsonify([dict(course) for course in courses])

@app.route('/api/admin/courses', methods=['POST'])
@token_required
def create_course(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    data = request.get_json()
    conn = get_db_connection()
    try:
        conn.execute('''
            INSERT INTO courses (course_name, description, required_subjects)
            VALUES (?, ?, ?)
        ''', (
            data['course_name'],
            data['description'],
            json.dumps(data['required_subjects'])
        ))
        conn.commit()
        return jsonify({'message': 'Course created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/update-weights', methods=['POST'])
@token_required
def update_recommender_weights(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Admin access required'}), 403
    
    try:
        new_weights = request.get_json()
        recommender.update_weights(new_weights)
        return jsonify({'status': 'Weights updated successfully'})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Update failed'}), 500
    
@app.route('/api/admin/users/<int:user_id>', methods=['GET', 'PUT', 'DELETE'])
@token_required
def manage_user(current_user, user_id):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    if request.method == 'GET':
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()
        return jsonify(dict(user)) if user else ('', 404)
        
    elif request.method == 'PUT':
        data = request.get_json()
        required_fields = ['firstName', 'lastName', 'username', 'email', 'educationLevel', 'is_admin']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400

        conn = get_db_connection()
        try:
            conn.execute('''
                UPDATE users 
                SET firstName=?, lastName=?, username=?, email=?, educationLevel=?, is_admin=?
                WHERE user_id=?
            ''', (
                data['firstName'],
                data['lastName'],
                data['username'],
                data['email'],
                data['educationLevel'],
                1 if data['is_admin'] else 0,
                user_id
            ))
            conn.commit()
            return jsonify({'status': 'User updated'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()
            
    elif request.method == 'DELETE':
        conn = get_db_connection()
        try:
            conn.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
            conn.commit()
            return jsonify({'status': 'User deleted'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()


@app.route('/api/admin/weights', methods=['GET', 'PUT'])
@token_required
def manage_weights(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    if request.method == 'GET':
        conn = get_db_connection()
        weights = conn.execute('''
            SELECT * FROM recommendation_weights 
            ORDER BY created_at DESC 
            LIMIT 1
        ''').fetchone()
        conn.close()

        if weights:
            return jsonify({
                'required_subjects': weights['required_subjects'],
                'interests': weights['interests'],
                'learning_preferences': weights['learning_preferences'],
                'personality_traits': weights['personality_traits'],
                'career_goals': weights['career_goals']
            })
        else:
            return jsonify({
                'required_subjects': 0.4,
                'interests': 0.2,
                'learning_preferences': 0.15,
                'personality_traits': 0.15,
                'career_goals': 0.1
            })

    if request.method == 'PUT':
        try:
            new_weights = request.get_json()
            required_keys = [
                'required_subjects', 'interests', 
                'learning_preferences', 'personality_traits', 
                'career_goals'
            ]

            # Validate presence of all required keys
            if not all(k in new_weights for k in required_keys):
                return jsonify({'error': 'Missing one or more required weight fields'}), 400

            # Validate individual values
            for k in required_keys:
                val = new_weights.get(k)
                if not isinstance(val, (int, float)) or not (0 <= val <= 1):
                    return jsonify({'error': f'Invalid value for {k}: must be a number between 0 and 1'}), 400

            # Validate total
            total = sum(new_weights[k] for k in required_keys)
            if abs(total - 1.0) > 0.01:
                return jsonify({'error': f'Weights must sum to 1.0 (current: {total:.2f})'}), 400

            # Save to database
            conn = get_db_connection()
            conn.execute(
                '''
                INSERT INTO recommendation_weights 
                (required_subjects, interests, learning_preferences, personality_traits, career_goals, created_at) 
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                ''',
                (
                    new_weights['required_subjects'],
                    new_weights['interests'],
                    new_weights['learning_preferences'],
                    new_weights['personality_traits'],
                    new_weights['career_goals']
                )
            )
            conn.commit()
            conn.close()

            # Update in-memory model
            recommender.update_weights(new_weights)

            return jsonify({'message': 'Weights updated successfully'}), 200

        except Exception as e:
            app.logger.error(f"Error updating weights: {str(e)}")
            return jsonify({'error': 'Server error updating weights'}), 500
    

@app.route('/api/admin/users/export')
@token_required
def export_users_csv(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()

    csv_data = 'User ID,Username,Email,Education Level,Admin Status\n'
    for user in users:
        csv_data += f"{user['user_id']},{user['username']},{user['email']},{user['educationLevel']},{'Yes' if user['is_admin'] else 'No'}\n"

    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-disposition': 'attachment; filename=users_export.csv'}
    )

@app.route('/api/admin/reports/export')
@token_required
def export_reports_csv(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db_connection()
    reports = conn.execute('''
        SELECT 
            courses.course_name AS "Course Name",
            COUNT(recommendations.recommendation_id) AS "Recommendations",
            AVG(recommendations.match_percentage) AS "Average Match %"
        FROM courses
        LEFT JOIN recommendations ON courses.course_id = recommendations.course_id
        GROUP BY courses.course_id
    ''').fetchall()
    conn.close()

    csv_data = 'courseName,recommendations,averageMatch\n'
    for report in reports:
        csv_data += f"{report['courseName']},{report['recommendations']},{report['averageMatch']:.2f}\n"

    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-disposition': 'attachment; filename=reports_export.csv'}
    )

@app.route('/api/admin/reports/usage-data')
@token_required
def usage_chart_data(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    conn = get_db_connection()
    
    # Get user registrations per day (last 30 days)
    registrations = conn.execute('''
        SELECT DATE(created_at) AS date, COUNT(*) AS count 
        FROM users 
        WHERE created_at > DATE('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''').fetchall()
    
    # Get assessments per day (last 30 days)
    assessments = conn.execute('''
        SELECT DATE(created_at) AS date, COUNT(*) AS count 
        FROM questionnaire_responses 
        WHERE created_at > DATE('now', '-30 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    ''').fetchall()
    
    conn.close()
    
    # Convert dates to ISO format
    registrations = [{"date": r['date'], "count": r['count']} for r in registrations]
    assessments = [{"date": a['date'], "count": a['count']} for a in assessments]
    
    return jsonify({
        'registrations': registrations,
        'assessments': assessments
    })

@app.route('/api/admin/reports/usage', methods=['GET'])
@token_required
def get_usage_reports(current_user):
    conn = get_db_connection()
    report = conn.execute('''
        SELECT DATE(created_at) AS date, COUNT(*) AS count
        FROM questionnaire_responses
        GROUP BY DATE(created_at)
        ORDER BY date DESC
        LIMIT 30
    ''').fetchall()
    conn.close()
    return jsonify([dict(r) for r in report])

@app.route('/api/admin/settings', methods=['GET'])
@token_required
def get_admin_settings(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Unauthorized'}), 403
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM system_settings ORDER BY id DESC LIMIT 1').fetchone()
    conn.close()
    if not row:
        return jsonify({'matchThreshold': 30, 'dataRetentionDays': 365, 'gradeMapping': {}})
    return jsonify({
        'matchThreshold': row['match_threshold'],
        'dataRetentionDays': row['data_retention_days'], 
        'gradeMapping': json.loads(row['grade_mapping'])
    })

@app.route('/api/admin/settings', methods=['PUT'])
@token_required
def update_admin_settings(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    grade_mapping = json.dumps(data.get('gradeMapping', {}))
    
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO system_settings (match_threshold, data_retention_days, grade_mapping)
        VALUES (?, ?, ?)
    ''', (
        int(data.get('matchThreshold', 30)),
        int(data.get('dataRetentionDays', 365)),
        grade_mapping
    ))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Settings updated successfully'}), 200

@app.route('/api/admin/settings', methods=['GET', 'PUT'])
@token_required
def system_settings(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    conn = get_db_connection()
    
    if request.method == 'PUT':
        try:
            data = request.get_json()
            
            # Validate inputs
            match_threshold = int(data.get('matchThreshold', 30))
            data_retention = int(data.get('dataRetentionDays', 365))
            grade_mapping = data.get('gradeMapping', {})
            
            # Validate grade mapping
            valid_grades = ['A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'D+', 'D', 'D-', 'E']
            for grade, value in grade_mapping.items():
                if grade not in valid_grades:
                    return jsonify({'error': f'Invalid grade: {grade}'}), 400
                try:
                    num_value = float(value)
                    if not 0.0 <= num_value <= 1.0:
                        return jsonify({'error': f'Value for {grade} must be between 0.0 and 1.0'}), 400
                except (TypeError, ValueError):
                    return jsonify({'error': f'Invalid value for {grade}'}), 400
            
            # Save to database
            conn.execute('''
                INSERT INTO system_settings (match_threshold, data_retention_days, grade_mapping)
                VALUES (?, ?, ?)
            ''', (match_threshold, data_retention, json.dumps(grade_mapping)))
            conn.commit()
            
            return jsonify({'message': 'Settings updated successfully'}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        finally:
            conn.close()
    
    # GET request
    try:
        row = conn.execute('''
            SELECT * FROM system_settings 
            ORDER BY id DESC 
            LIMIT 1
        ''').fetchone()
        
        if row:
            return jsonify({
                'matchThreshold': row['match_threshold'],
                'dataRetentionDays': row['data_retention_days'],
                'gradeMapping': json.loads(row['grade_mapping'])
            })
        else:
            return jsonify({
                'matchThreshold': 30,
                'dataRetentionDays': 365,
                'gradeMapping': {}
            })
    finally:
        conn.close()

@app.route('/api/admin/activity-log', methods=['GET'])
@token_required
def get_activity_logs(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    date_filter = request.args.get('date')
    conn = get_db_connection()
    try:
        query = '''
            SELECT admin_logs.timestamp, admin_logs.action, admin_logs.target_type, 
                   admin_logs.target_id, users.username
            FROM admin_logs 
            JOIN users ON admin_logs.user_id = users.user_id
        '''
        params = []
        if date_filter:
            query += " WHERE DATE(admin_logs.timestamp) = ?"
            params.append(date_filter)
        query += " ORDER BY admin_logs.timestamp DESC LIMIT 100"
        rows = conn.execute(query, params).fetchall()

        # Build a Python list of dicts
        log_list = [
            {
                'timestamp': row['timestamp'],
                'username': row['username'],
                'action': row['action'],
                'target_type': row['target_type'],
                'target_id': row['target_id']
            }
            for row in rows
        ]
        # returns a list
        return jsonify(log_list)
    finally:
        conn.close()




@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password(current_user):  
    data = request.get_json()
    
    # Add validation for required fields
    required_fields = ['current_password', 'new_password']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'Missing {field}'}), 400

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (current_user['user_id'],)).fetchone()
    
    # Verify current password
    if not check_password_hash(user['password_hash'], data['current_password']):
        conn.close()
        return jsonify({'error': 'Current password is incorrect'}), 401

    # Update to new password
    new_hash = generate_password_hash(data['new_password'])
    conn.execute('''
        UPDATE users 
        SET password_hash = ?
        WHERE user_id = ?
    ''', (new_hash, current_user['user_id']))
    
    conn.commit()
    conn.close()
    return jsonify({'message': 'Password updated successfully'}), 200

@app.route('/api/admin/users/<int:user_id>/reset-password', methods=['POST'])
@token_required
def admin_reset_user_password(current_user, user_id):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT email FROM users WHERE user_id = ?', (user_id,)).fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate temporary password
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        hashed_pw = generate_password_hash(temp_password)
        
        # Update user
        conn.execute('''
            UPDATE users 
            SET password_hash = ?, password_reset_required = 1 
            WHERE user_id = ?
        ''', (hashed_pw, user_id))
        conn.commit()
        
        # Send email
        msg = MIMEText(f'Your temporary password is: {temp_password}\n\nPlease change it after logging in.')
        msg['Subject'] = 'Password Reset Notification'
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = user['email']
        
        server = None
        try:
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        except Exception as e:
            app.logger.error(f"Error sending email: {str(e)}")
            return jsonify({'error': 'Failed to send email'}), 500
        finally:
            if server:
                try:
                    
                    server.close()
                except Exception as quit_error:
                    app.logger.error(f"Error closing SMTP connection: {str(quit_error)}")
        
        return jsonify({
            'message': f'Password reset for user {user_id}. Temporary password sent to email.',
            'temporary_password': temp_password
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

def generate_temp_password(length=12):
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

@app.route('/api/admin/reports/top-courses')
@token_required
def top_courses_report(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db_connection()
    try:
        # Execute query and get results
        rows = conn.execute('''
            SELECT 
                courses.course_name AS courseName,
                COUNT(recommendations.recommendation_id) AS recommendations,
                COALESCE(ROUND(AVG(recommendations.match_percentage), 1), 0) AS averageMatch
            FROM courses
            LEFT JOIN recommendations ON courses.course_id = recommendations.course_id
            GROUP BY courses.course_id
            ORDER BY recommendations DESC, averageMatch DESC
            LIMIT 10
        ''').fetchall()
        
        # Convert rows to proper format
        results = []
        for row in rows:
            results.append({
                'courseName': row['courseName'],
                'recommendations': row['recommendations'],
                'averageMatch': row['averageMatch']
            })
            
        return jsonify(results)
        
    except sqlite3.Error as e:
        app.logger.error(f"Database error in top_courses_report: {str(e)}")
        return jsonify({'error': 'Database query failed'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error in top_courses_report: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        conn.close()
    
    # Convert rows to proper format
    results = []
    for row in rows:
        results.append({
            'courseName': row['courseName'],
            'recommendations': row['recommendations'],
            'averageMatch': row['averageMatch']
        })
    
    return jsonify(results)

@app.route('/api/admin/system/restore', methods=['POST'])
@token_required
def restore_backup(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    if 'backup' not in request.files:
        return jsonify({'error': 'No backup file provided'}), 400
    
    file = request.files['backup']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    try:
        # Save to temp file
        temp_path = os.path.join('/tmp', file.filename)
        file.save(temp_path)
        
        # Validate zip file
        if not zipfile.is_zipfile(temp_path):
            return jsonify({'error': 'Invalid backup file'}), 400
        
        # Create temp dir
        restore_dir = os.path.join('/tmp', 'restore')
        os.makedirs(restore_dir, exist_ok=True)
        
        # Extract files
        with zipfile.ZipFile(temp_path, 'r') as zip_ref:
            zip_ref.extractall(restore_dir)
        
        # Find database file
        db_file = None
        for root, dirs, files in os.walk(restore_dir):
            for file in files:
                if file.endswith('.sqlite'):
                    db_file = os.path.join(root, file)
                    break
            if db_file:
                break
        
        if not db_file:
            return jsonify({'error': 'Database file not found in backup'}), 400
        
        # Replace current database
        shutil.copyfile(db_file, DATABASE)
        
        # Reinitialize recommender
        global recommender
        recommender = MajorRecommender('newcuea-majors-mapping.csv')
        
        return jsonify({
            'message': 'System restored successfully. Application will restart.'
        }), 200
    except Exception as e:
        app.logger.error(f"Restore error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        try:
            os.remove(temp_path)
            shutil.rmtree(restore_dir)
        except:
            pass

@app.route('/api/admin/system/backup', methods=['POST'])
@token_required
def create_backup(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403
    
    try:
        # Create in-memory zip file
        buffer = io.BytesIO()
        
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add database
            zipf.write(DATABASE, os.path.basename(DATABASE))
            
            # Add CSV data
            csv_files = ['newcuea-majors-mapping.csv']
            for file in csv_files:
                if os.path.exists(file):
                    zipf.write(file, os.path.basename(file))
        
        buffer.seek(0)
        
        return send_file(
            buffer,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'courseadvisor_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip'
        )
    except Exception as e:
        app.logger.error(f"Backup creation error: {str(e)}")
        return jsonify({'error': 'Failed to create backup'}), 500

@app.route('/api/admin/stats', methods=['GET'])
@token_required
@cache.cached(timeout=300)
def dashboard_stats(current_user):
    if not current_user['is_admin']:
        return jsonify({'error': 'Forbidden'}), 403

    conn = get_db_connection()
    try:
        # Current counts
        users_current = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        assessments_current = conn.execute('SELECT COUNT(*) FROM questionnaire_responses').fetchone()[0]
        courses_current = conn.execute('SELECT COUNT(*) FROM courses').fetchone()[0]
        
        # Previous period counts (last 30 days) - only for users and assessments
        prev_period = datetime.now(UTC) - timedelta(days=30)
        prev_period_str = prev_period.strftime('%Y-%m-%d %H:%M:%S')
        
        # Calculate trends
        def calculate_trend(current, prev):
            if prev == 0:
                return 100 if current > 0 else 0
            return round(((current - prev) / prev) * 100, 1)
        
        users_prev = conn.execute(
            'SELECT COUNT(*) FROM users WHERE created_at < ?',
            (prev_period_str,)
        ).fetchone()[0]
        users_trend = calculate_trend(users_current, users_prev)
        
        assessments_prev = conn.execute(
            'SELECT COUNT(*) FROM questionnaire_responses WHERE created_at < ?',
            (prev_period_str,)
        ).fetchone()[0]
        assessments_trend = calculate_trend(assessments_current, assessments_prev)
        
        # Courses don't have trend data
        courses_trend = None
        
        return jsonify({
            'users': users_current,
            'assessments': assessments_current,
            'courses': courses_current,
            'users_trend': users_trend,
            'assessments_trend': assessments_trend,
            'courses_trend': courses_trend
        }), 200
    finally:
        conn.close()

@app.route('/test-token')
def test_token():
    token = request.args.get('token')
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='password-reset', max_age=3600)
        return f"Token valid for {email}"
    except Exception as e:
        return f"Token invalid: {str(e)}"
    
if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True, use_reloader=False)

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    educationLevel TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME ,
    is_admin BOOLEAN DEFAULT 0 ,
    password_reset_required BOOLEAN DEFAULT 0,
    is_verified BOOLEAN DEFAULT 0,
    verification_token TEXT,
    token_expiration DATETIME,
    reset_token TEXT,
    reset_token_expiration DATETIME
);

CREATE TABLE IF NOT EXISTS courses (
    course_id INTEGER PRIMARY KEY AUTOINCREMENT,
    course_name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL,
    required_subjects TEXT NOT NULL,
    career_paths TEXT NOT NULL,
    program_type TEXT NOT NULL,
    minimum_grade TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS questionnaire_responses (
    response_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    response_data JSON NOT NULL CHECK(json_valid(response_data)),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (user_id)
);

CREATE TABLE IF NOT EXISTS recommendations (
    recommendation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    course_id INTEGER NOT NULL,
    match_percentage REAL NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    feedback_score INTEGER DEFAULT -1,
    viewed BOOLEAN DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users (user_id),
    FOREIGN KEY (course_id) REFERENCES courses (course_id)
);

CREATE TABLE IF NOT EXISTS admin_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS recommendation_weights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    required_subjects REAL NOT NULL,
    interests REAL NOT NULL,
    learning_preferences REAL NOT NULL,
    personality_traits REAL NOT NULL,
    career_goals REAL NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS system_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,
    match_threshold INTEGER DEFAULT 30,
    data_retention_days INTEGER DEFAULT 365,
    grade_mapping TEXT DEFAULT '{"A":1.0,"A-":0.9,"B+":0.8,"B":0.7,"B-":0.6,"C+":0.5,"C":0.4,"C-":0.3,"D+":0.2,"D":0.1,"D-":0.0,"E":0.0}'
);


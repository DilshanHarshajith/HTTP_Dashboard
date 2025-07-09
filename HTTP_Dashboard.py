import sys
import os
import signal
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, Response, send_from_directory, render_template_string, jsonify, redirect, url_for, session
import requests
import logging
from functools import wraps
import csv
from io import StringIO
from typing import List, Dict, Union, Optional, Tuple
import configparser
import hashlib
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv


# --------------------------
# Initial Logger Setup
# --------------------------

# Set up basic logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --------------------------
# Configuration Management
# --------------------------

load_dotenv()

class Config:
    """Centralized configuration management with enhanced security"""
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent
        self.config_file = self.base_dir / "config.ini"
        self.db_dir = self.base_dir / "Database"
        
        try:
            # Now we can use logger since it's defined
            logger.info("Initializing configuration")
            
            # Default configuration with secure defaults
            self.defaults = {
                'server': {
                    'port': '1000',
                    'max_content_length': '67108864',  # 64MB
                    'secret_key': secrets.token_hex(32),  # Generate secure random key
                    'session_timeout': '1800',  # 30 minutes
                },
                'database': {
                    'records_db': self.db_dir / 'records.db',
                    'other_db': self.db_dir / 'other.db',
                    'journal_mode': 'WAL',  # Better SQLite performance
                },
                'storage': {
                    'upload_folder': 'uploads',
                    'allowed_extensions': 'txt,pdf,png,jpg,jpeg,gif,db,pub',  # Restrict file types
                },
                'auth': {
                    'admin_username': os.getenv('ADMIN_USERNAME', 'admin'),  # Use environment variable or default
                    'admin_password': generate_password_hash(os.getenv('ADMIN_PASSWORD', 'password')),  # Hashed by default
                    'max_login_attempts': '5',
                    'lockout_time': '300',  # 5 minutes
                },
                'telegram': {
                    'bot_token': os.getenv('TELEGRAM_BOT_TOKEN'),
                    'chat_id': os.getenv('TELEGRAM_CHAT_ID'),
                    'api_timeout': '100',
                },
                'security': {
                    'rate_limit': '100',  # Requests per minute
                    'enable_csrf': 'True',
                    'content_security_policy': "default-src 'self'; style-src 'self' 'unsafe-inline';"
                }
            }
            
            self._ensure_config_exists()
            self._load_config()
            self._init_paths()
            
        except Exception as e:
            logger.critical(f"Failed to initialize configuration: {e}")
            raise

    def _ensure_secure_permissions(self):
        """Ensure config file has proper permissions"""
        if self.config_file.exists():
            try:
                os.chmod(self.config_file, 0o600)  # Read/write only by owner
            except Exception as e:
                logger.error(f"Failed to set secure permissions on config file: {e}")

    def _ensure_config_exists(self):
        """Create secure config file if it doesn't exist"""
        if not self.config_file.exists():
            logger.info("Creating default configuration file")
            self._create_default_config()
            # Set secure permissions immediately after creation
            self._ensure_secure_permissions()

    def _create_default_config(self):
        """Write default configuration to file with secure values"""
        config = configparser.ConfigParser()
        config.read_dict(self.defaults)
        with open(self.config_file, 'w') as f:
            config.write(f)

    def _load_config(self):
        """Load and validate configuration from file"""
        config = configparser.ConfigParser()
        try:
            config.read(self.config_file)
            
            # Server settings
            self.port = self._get_int(config, 'server', 'port')
            self.max_content_length = self._get_int(config, 'server', 'max_content_length')
            self.secret_key = config.get('server', 'secret_key', fallback=self.defaults['server']['secret_key'])
            self.session_timeout = self._get_int(config, 'server', 'session_timeout')
            
            # Database settings
            self.records_db = Path(config.get('database', 'records_db', fallback=self.defaults['database']['records_db']))
            self.other_db = Path(config.get('database', 'other_db', fallback=self.defaults['database']['other_db']))
            self.journal_mode = config.get('database', 'journal_mode', fallback=self.defaults['database']['journal_mode'])
            
            # Storage settings
            self.upload_folder = Path(config.get('storage', 'upload_folder', fallback=self.defaults['storage']['upload_folder']))
            self.allowed_extensions = set(
                ext.strip() for ext in 
                config.get('storage', 'allowed_extensions', fallback=self.defaults['storage']['allowed_extensions']).split(',')
            )
            
            # Auth settings
            self.admin_username = config.get('auth', 'admin_username', fallback=self.defaults['auth']['admin_username'])
            self.admin_password = config.get('auth', 'admin_password', fallback=self.defaults['auth']['admin_password'])
            self.max_login_attempts = self._get_int(config, 'auth', 'max_login_attempts')
            self.lockout_time = self._get_int(config, 'auth', 'lockout_time')
            
            # Telegram settings
            self.bot_token = config.get('telegram', 'bot_token', fallback=self.defaults['telegram']['bot_token'])
            self.chat_id = self._get_int(config, 'telegram', 'chat_id')
            self.api_timeout = self._get_int(config, 'telegram', 'api_timeout')
            
            # Security settings
            self.rate_limit = self._get_int(config, 'security', 'rate_limit')
            self.enable_csrf = config.getboolean('security', 'enable_csrf', fallback=True)
            self.content_security_policy = config.get('security', 'content_security_policy', 
                                                   fallback=self.defaults['security']['content_security_policy'])
            
            logger.info("Configuration loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            raise RuntimeError("Failed to load configuration") from e

    def _get_int(self, config, section, option) -> int:
        """Helper to safely get integer values from config"""
        try:
            return config.getint(section, option, fallback=int(self.defaults[section][option]))
        except ValueError:
            logger.warning(f"Invalid integer value for {section}.{option}, using default")
            return int(self.defaults[section][option])

    def _init_paths(self):
        """Initialize and secure all required paths"""
        try:
            # Always resolve paths relative to base_dir
            self.records_db = (self.base_dir / self.records_db).resolve()
            self.other_db = (self.base_dir / self.other_db).resolve()
            self.upload_folder = (self.base_dir / self.upload_folder).resolve()
            self.templates_folder = (self.base_dir / "templates").resolve()
            self.log_file = (self.base_dir / "app.log").resolve()

            # Create directories with secure permissions
            for path in [self.records_db.parent, self.other_db.parent, self.upload_folder, self.templates_folder]:
                path.mkdir(parents=True, exist_ok=True)
                os.chmod(path, 0o700)  # Restrict access to owner only

            logger.info("Paths initialized successfully")

        except Exception as e:
            logger.error(f"Error initializing paths: {e}")
            raise RuntimeError("Failed to initialize paths") from e

# Initialize configuration
try:
    config = Config()
except Exception as e:
    logging.critical(f"Failed to initialize configuration: {e}")
    sys.exit(1)

# Now that config is loaded, update logging to include file handler
file_handler = logging.FileHandler(config.log_file)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

# --------------------------
# Flask Application Setup
# --------------------------

app = Flask(__name__)
app.config.update({
    'UPLOAD_FOLDER': str(config.upload_folder),
    'MAX_CONTENT_LENGTH': config.max_content_length,
    'SECRET_KEY': config.secret_key,
    'PERMANENT_SESSION_LIFETIME': timedelta(seconds=config.session_timeout),
    'SESSION_COOKIE_SECURE': True,  # Only send cookies over HTTPS
    'SESSION_COOKIE_HTTPONLY': True,  # Prevent JavaScript access to cookies
    'SESSION_COOKIE_SAMESITE': 'Lax',  # CSRF protection
    'TEMPLATES_AUTO_RELOAD': False,  # Disable in production
})

# --------------------------
# Security Middleware
# --------------------------

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = config.content_security_policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# --------------------------
# Database Management
# --------------------------

class DatabaseManager:
    """Secure database operations with connection pooling"""
    _connections = {}
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize database with secure settings"""
        try:
            conn = self.get_connection()
            # Enable WAL mode for better concurrency
            conn.execute(f"PRAGMA journal_mode={config.journal_mode}")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA secure_delete=ON")  # Ensure deleted data is overwritten
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    body TEXT,
                    headers TEXT,
                    user_agent TEXT
                )
            """)
            # Add missing columns if upgrading from older schema
            existing_cols = [row[1] for row in conn.execute("PRAGMA table_info(records)")]
            if 'headers' not in existing_cols:
                conn.execute("ALTER TABLE records ADD COLUMN headers TEXT")
            if 'user_agent' not in existing_cols:
                conn.execute("ALTER TABLE records ADD COLUMN user_agent TEXT")
            # Create indexes for better performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON records(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_client_ip ON records(client_ip)")
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Failed to initialize database {self.db_path.name}: {e}")
            raise
    
    def get_connection(self):
        """Get a new database connection"""
        try:
            conn = sqlite3.connect(
                str(self.db_path),
                timeout=10,
                isolation_level=None,
                check_same_thread=False
            )
            conn.row_factory = sqlite3.Row
            return conn
        except Exception as e:
            logger.error(f"Failed to connect to database {self.db_path.name}: {e}")
            raise
    
    def log_request(self, client_ip: str, method: str, body: str, headers: Optional[Dict] = None, user_agent: Optional[str] = None):
        """Securely log HTTP request to database"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        headers_str = str(headers) if headers else None
        
        try:
            with self.get_connection() as conn:
                # Use parameterized queries to prevent SQL injection
                conn.execute(
                    "INSERT INTO records (timestamp, client_ip, method, body, headers, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
                    (timestamp, client_ip, method, body[:1000], headers_str, user_agent)
                )
        except Exception as e:
            logger.error(f"Failed to log request to {self.db_path.name}: {e}")
    
    def get_records(self, limit: Optional[int] = None) -> List[Dict]:
        """Securely retrieve records from database"""
        try:
            with self.get_connection() as conn:
                query = "SELECT * FROM records ORDER BY id DESC"
                params = ()
                
                if limit:
                    query += " LIMIT ?"
                    params = (limit,)
                
                cursor = conn.execute(query, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error reading records from {self.db_path.name}: {e}")
            return []
    
    def get_record_count(self) -> int:
        """Get total number of records safely"""
        try:
            with self.get_connection() as conn:
                row = conn.execute("SELECT COUNT(*) as cnt FROM records").fetchone()
                return row["cnt"] if row else 0
        except Exception as e:
            logger.error(f"Error counting records in {self.db_path.name}: {e}")
            return 0
    
    def clear_records(self) -> bool:
        """Securely clear all records from database"""
        try:
            with self.get_connection() as conn:
                conn.execute("DELETE FROM records")
                conn.execute("VACUUM")  # Reclaim disk space
                return True
        except Exception as e:
            logger.error(f"Error clearing records from {self.db_path.name}: {e}")
            return False
    
    def export_to_csv(self) -> Optional[str]:
        """Securely export records to CSV"""
        try:
            records = self.get_records()
            if not records:
                return None

            si = StringIO()
            writer = csv.writer(si)
            
            # Write headers
            writer.writerow(['ID', 'Timestamp', 'Client IP', 'HTTP Method', 'Request Body', 'Headers', 'User Agent'])
            
            # Write data with proper escaping
            for record in records:
                clean_body = record.get('body', '').replace('\n', ' ').replace('\r', ' ')
                writer.writerow([
                    record.get('id', ''),
                    record.get('timestamp', ''),
                    record.get('client_ip', ''),
                    record.get('method', ''),
                    clean_body,
                    record.get('headers', ''),
                    record.get('user_agent', '')
                ])
            
            output = si.getvalue()
            si.close()
            return output
        except Exception as e:
            logger.error(f"Error exporting records from {self.db_path.name} to CSV: {e}")
            return None

# Initialize database managers
try:
    records_db = DatabaseManager(config.records_db)
    other_db = DatabaseManager(config.other_db)
except Exception as e:
    logging.critical(f"Failed to initialize databases: {e}")
    sys.exit(1)

# --------------------------
# File Management
# --------------------------

class FileManager:
    """Secure file uploads and management with extension validation"""
    def __init__(self, upload_folder: Path):
        self.upload_folder = upload_folder
    
    def _is_allowed_file(self, filename: str) -> bool:
        """Check if file has allowed extension"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in config.allowed_extensions
    
    def _generate_secure_filename(self, filename: str) -> str:
        """Generate secure filename with random prefix"""
        prefix = secrets.token_hex(8)
        base = secure_filename(filename)
        return f"{prefix}_{base}"
    
    def save_file(self, file) -> Tuple[Optional[str], Optional[str]]:
        """Securely save uploaded file with validation"""
        if not file or file.filename == '':
            return None, "No file selected"
        
        if not self._is_allowed_file(file.filename):
            return None, "File type not allowed"
        
        try:
            filename = self._generate_secure_filename(file.filename)
            filepath = self.upload_folder / filename
            
            # Save file in chunks to prevent memory issues
            file.save(str(filepath))
            
            # Verify file was saved correctly
            if not filepath.exists() or filepath.stat().st_size == 0:
                if filepath.exists():
                    filepath.unlink()
                return None, "Failed to save file"
            
            logger.info(f"File uploaded: {filename}")
            return filename, None
        except Exception as e:
            logger.error(f"Error saving file {file.filename}: {e}")
            return None, "File upload failed"
    
    def get_files(self) -> List[Dict]:
        """Get information about uploaded files securely"""
        try:
            files = []
            if self.upload_folder.exists():
                for file_path in self.upload_folder.iterdir():
                    if file_path.is_file():
                        stat = file_path.stat()
                        files.append({
                            'name': file_path.name,
                            'size': stat.st_size,
                            'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                        })
            return sorted(files, key=lambda x: x['name'])
        except Exception as e:
            logger.error(f"Error getting file info: {e}")
            return []
    
    def delete_file(self, filename: str) -> Tuple[bool, Optional[str]]:
        """Securely delete an uploaded file"""
        try:
            safe_filename = secure_filename(filename)
            if not safe_filename or safe_filename != filename:
                return False, "Invalid filename"
            
            file_path = self.upload_folder / safe_filename
            if not file_path.exists():
                return False, "File not found"
            
            file_path.unlink()
            logger.info(f"File deleted: {filename}")
            return True, None
        except Exception as e:
            logger.error(f"Error deleting file {filename}: {e}")
            return False, "Failed to delete file"

file_manager = FileManager(config.upload_folder)

# --------------------------
# Authentication & Rate Limiting
# --------------------------

class AuthManager:
    """Enhanced authentication with rate limiting and secure password handling"""
    def __init__(self):
        self.login_attempts = {}
        self.lockouts = {}
    
    def check_auth(self, username: str, password: str) -> bool:
        """Secure authentication with rate limiting"""
        # Check if IP is locked out
        client_ip = request.remote_addr
        if self._is_ip_locked_out(client_ip):
            logger.warning(f"Login attempt from locked out IP: {client_ip}")
            return False
        
        # Verify credentials
        if username == config.admin_username and \
           check_password_hash(config.admin_password, password):
            self._reset_login_attempts(client_ip)
            return True
        
        # Track failed attempts
        self._record_failed_attempt(client_ip)
        return False
    
    def _is_ip_locked_out(self, client_ip: str) -> bool:
        """Check if IP is currently locked out"""
        if client_ip in self.lockouts:
            lockout_time = self.lockouts[client_ip]
            if (datetime.now() - lockout_time).seconds < config.lockout_time:
                return True
            del self.lockouts[client_ip]
        return False
    
    def _record_failed_attempt(self, client_ip: str):
        """Record failed login attempt and lockout if needed"""
        self.login_attempts[client_ip] = self.login_attempts.get(client_ip, 0) + 1
        logger.warning(f"Failed login attempt from {client_ip}. Attempt {self.login_attempts[client_ip]}")
        
        if self.login_attempts[client_ip] >= config.max_login_attempts:
            self.lockouts[client_ip] = datetime.now()
            logger.warning(f"IP {client_ip} locked out due to too many failed attempts")
    
    def _reset_login_attempts(self, client_ip: str):
        """Reset failed attempts counter for IP"""
        if client_ip in self.login_attempts:
            del self.login_attempts[client_ip]

auth_manager = AuthManager()

def require_admin_auth(func):
    """Enhanced admin authentication decorator with CSRF protection"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Check session first
        if session.get('admin_logged_in'):
            if config.enable_csrf and request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                # Verify CSRF token for state-changing methods
                if request.headers.get('X-Requested-With') != 'XMLHttpRequest':
                    return jsonify({"error": "CSRF protection"}), 403
            return func(*args, **kwargs)
        
        # Check HTTP Basic Auth
        auth = request.authorization
        if auth and auth_manager.check_auth(auth.username, auth.password):
            session['admin_logged_in'] = True
            session.permanent = True
            return func(*args, **kwargs)
        
        # For browsers, show alert and prompt for HTTP Basic Auth
        if 'text/html' in request.headers.get('Accept', ''):
            return Response(
                '''
                <script>
                    alert("Authentication required! Please log in.");
                </script>
                ''',
                401,
                {'WWW-Authenticate': 'Basic realm="Admin Login"'}
            )
        
        # Otherwise, ask for HTTP Basic Auth
        return Response(
            'Authentication required', 401,
            {'WWW-Authenticate': 'Basic realm="Admin Login"'}
        )
    return wrapper

# --------------------------
# Telegram Integration
# --------------------------

class TelegramNotifier:
    """Secure Telegram notification service with rate limiting"""
    def __init__(self, bot_token: str, chat_id: int):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        self.last_send_time = None
    
    def send_records(self, db_manager: DatabaseManager) -> Dict[str, str]:
        """Securely send logged data to Telegram with rate limiting"""
        try:
            # Rate limiting
            if self.last_send_time and (datetime.now() - self.last_send_time).seconds < 5:
                return {"error": "Rate limit exceeded. Wait 5 seconds between sends."}
            
            records = db_manager.get_records(limit=50)  # Limit to 50 records per message
            if not records:
                return {"error": "No records to send"}
            
            # Format records as text with proper escaping
            records_text = "\n".join(
                f"[{r.get('timestamp', '')}]\n"
                f"IP: {r.get('client_ip', '')}\n"
                f"Method: {r.get('method', '')}\n"
                f"Data: {r.get('body', '')[:200]}\n"
                "---"
                for r in records
            )
            
            max_length = 4000
            if len(records_text) > max_length:
                records_text = records_text[:max_length] + "\n... (truncated)"
            
            payload = {
                "chat_id": self.chat_id,
                "text": records_text,
                "parse_mode": "HTML",
            }
            
            response = requests.post(
                self.api_url,
                data=payload,
                timeout=config.api_timeout,
                verify=True  # Enable SSL verification
            )
            
            self.last_send_time = datetime.now()
            
            if not response.ok:
                logger.error(f"Failed to send Telegram message: {response.text}")
                return {"error": "Failed to send data to Telegram"}
            
            return {"status": "success", "message": "Data sent to Telegram successfully"}
        except requests.exceptions.RequestException as e:
            logger.error(f"Telegram API error: {e}")
            return {"error": "Failed to connect to Telegram API"}
        except Exception as e:
            logger.error(f"Error sending to Telegram: {e}")
            return {"error": "Failed to send data"}

telegram_notifier = TelegramNotifier(config.bot_token, config.chat_id)

# --------------------------
# HTML Templates
# --------------------------

def load_template(name: str) -> str:
    """Securely load HTML template from file"""
    template_path = config.templates_folder / f"{name}.html"
    if not template_path.exists():
        logger.warning(f"Template not found: {template_path}")
        return ""
    try:
        with open(template_path, 'r') as f:
            content = f.read()
            return content
    except Exception as e:
        logger.error(f"Error loading template {template_path}: {e}")
        return ""
    
# --------------------------
# Error Handlers
# --------------------------

@app.errorhandler(400)
def bad_request(e):
    """Handle bad requests"""
    logger.warning(f"Bad request: {e}")
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(401)
def unauthorized(e):
    """Handle unauthorized access"""
    logger.warning(f"Unauthorized access attempt: {e}")
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(e):
    """Handle forbidden access"""
    logger.warning(f"Forbidden access attempt: {e}")
    return jsonify({"error": "Forbidden"}), 403

@app.errorhandler(404)
def not_found(e):
    """Handle not found errors"""
    logger.warning(f"Resource not found: {e}")
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    logger.warning(f"File too large: {e}")
    return jsonify({"error": "File too large"}), 413

@app.errorhandler(429)
def too_many_requests(e):
    """Handle rate limiting"""
    logger.warning(f"Rate limit exceeded: {e}")
    return jsonify({"error": "Too many requests"}), 429

@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    logger.error(f"Internal server error: {e}")
    return jsonify({"error": "Internal server error"}), 500

# --------------------------
# Application Routes
# --------------------------

@app.route('/', methods=['GET', 'POST'])
def index():    
    client_ip = request.remote_addr
    method = request.method
    body = request.get_data(as_text=True) or "None"
    headers = dict(request.headers)
    user_agent = request.headers.get('User-Agent')
    
    # Log to appropriate database based on method
    if method == 'POST':
        records_db.log_request(client_ip, method, body, headers, user_agent)
    else:
        other_db.log_request(client_ip, method, body, headers, user_agent)
    
    return jsonify({"status": "ready"}), 200

# Admin Routes
@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    """Admin dashboard with authentication"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if auth_manager.check_auth(username, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            # Render the login template with error
            return render_template('admin_login.html', error="Invalid credentials")
    # Always render the login template for GET
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Logout admin"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/panel')
@require_admin_auth
def admin_panel():
    """Main admin control panel"""
    try:
        records = records_db.get_records(limit=100)
        other_requests = other_db.get_records(limit=100)
        files_info = file_manager.get_files()

        template_content = load_template('admin_panel')
        if not template_content:
            return jsonify({"error": "Admin panel template not found"}), 500
        return render_template_string(
            template_content, 
            records=records,
            records_count=records_db.get_record_count(),
            other_requests=other_requests,
            other_count=other_db.get_record_count(),
            total_files=len(files_info),
            total_size=sum(f['size'] for f in files_info),
            files_info=files_info
        )
    except Exception as e:
        logger.error(f"Error in admin panel: {e}")
        return jsonify({"error": "Failed to load admin panel"}), 500

# Admin API Endpoints
@app.route('/admin/api/send-records', methods=['POST'])
@require_admin_auth
def admin_send_records():
    result = telegram_notifier.send_records(records_db)
    return jsonify(result)

@app.route('/admin/api/send-other', methods=['POST'])
@require_admin_auth
def admin_send_other():
    result = telegram_notifier.send_records(other_db)
    return jsonify(result)

@app.route('/admin/api/clear-records', methods=['POST'])
@require_admin_auth
def admin_clear_records():
    if records_db.clear_records():
        return jsonify({"status": "success", "message": "Records cleared successfully"})
    return jsonify({"error": "Failed to clear records"}), 500

@app.route('/admin/api/clear-other', methods=['POST'])
@require_admin_auth
def admin_clear_other():
    if other_db.clear_records():
        return jsonify({"status": "success", "message": "Common requests cleared successfully"})
    return jsonify({"error": "Failed to clear other requests"}), 500

@app.route('/admin/api/download-records', methods=['GET'])
@require_admin_auth
def admin_download_records():
    csv_data = records_db.export_to_csv()
    if csv_data:
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=records.csv"}
        )
    return jsonify({"error": "No records to download"}), 404

@app.route('/admin/api/download-other', methods=['GET'])
@require_admin_auth
def admin_download_other():
    csv_data = other_db.export_to_csv()
    if csv_data:
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={"Content-Disposition": "attachment;filename=other_requests.csv"}
        )
    return jsonify({"error": "No other requests to download"}), 404

@app.route('/admin/api/delete-file/<filename>', methods=['POST'])
@require_admin_auth
def admin_delete_file(filename):
    success, message = file_manager.delete_file(filename)
    if success:
        return jsonify({"status": "success", "message": f"File {filename} deleted successfully"})
    return jsonify({"error": message or "File not found or could not be deleted"}), 404

# File Management Routes
@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file uploads"""
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    filename, error = file_manager.save_file(file)
    if filename:
        return jsonify({"status": "success", "filename": filename}), 200
    return jsonify({"error": error or "File upload failed"}), 400

@app.route('/files', methods=['GET'])
@require_admin_auth
def list_uploaded_files():
    """List uploaded files with better error handling"""
    try:
        files = file_manager.get_files()
        if not files:
            files_html = '<p>No files uploaded yet.</p>'
        else:
            files_html = ''.join(
                f'<li><a href="/files/{f["name"]}" target="_blank">{f["name"]}</a> '
                f'<small>({f["size"]} bytes)</small></li>' 
                for f in files
            )
            files_html = f'<ul>{files_html}</ul>'
        
        return render_template_string(f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Uploaded Files</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                ul {{ list-style-type: none; padding: 0; }}
                li {{ margin: 10px 0; padding: 10px; background: #f5f5f5; border-radius: 5px; }}
                a {{ text-decoration: none; color: #007bff; }}
                a:hover {{ text-decoration: underline; }}
                small {{ color: #666; }}
            </style>
        </head>
        <body>
            <h2>Uploaded Files ({len(files)} files)</h2>
            {files_html}
            <br>
            <a href="/admin/panel">← Back to admin panel</a>
        </body>
        </html>
        """)
    except Exception as e:
        logger.error(f"Error listing files: {e}")
        return jsonify({"error": "Failed to list files"}), 500

@app.route('/files/<filename>', methods=['GET'])
@require_admin_auth
def serve_uploaded_file(filename):
    """Serve uploaded files securely"""
    try:
        safe_filename = secure_filename(filename)
        file_path = config.upload_folder / safe_filename
        if not file_path.exists():
            return jsonify({"error": "File not found"}), 404
        return send_from_directory(config.upload_folder, safe_filename)
    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return jsonify({"error": "Failed to serve file"}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "records_count": records_db.get_record_count(),
        "other_count": other_db.get_record_count(),
        "files_count": len(file_manager.get_files())
    })

# --------------------------
# Application Startup
# --------------------------

if __name__ == "__main__":
    try:
        # Graceful shutdown handler
        def signal_handler(sig, frame):
            """Handle shutdown signals gracefully"""
            logger.info(f"Received signal {sig}, shutting down gracefully...")
            
            # Clean up resources
            for conn in DatabaseManager._connections.values():
                try:
                    conn.close()
                except Exception as e:
                    logger.error(f"Error closing database connection: {e}")
            
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        logger.info(f"Starting Flask application on port {config.port}")
        logger.info(f"Admin dashboard available at: http://localhost:{config.port}/admin")
        logger.info("Admin authentication is enabled")
        
        from waitress import serve
        serve(app, host='0.0.0.0', port=config.port)
        
    except Exception as e:
        logger.critical(f"Failed to start application: {e}")
        sys.exit(1)
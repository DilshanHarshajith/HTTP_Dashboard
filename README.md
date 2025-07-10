# HTTP Dashboard

A secure Flask-based web application for logging and managing HTTP requests with an admin dashboard, file upload capabilities, and Telegram integration.

## Features

- **HTTP Request Logging**: Automatically logs all incoming HTTP requests (GET, POST, etc.) to SQLite databases
- **Admin Dashboard**: Web-based interface for managing logged requests and files
- **File Upload Management**: Secure file upload with extension validation and management
- **Telegram Integration**: Send logged data directly to Telegram
- **Database Export**: Export logged data to CSV format
- **Enhanced Security**: Authentication, rate limiting, CSRF protection, and secure headers
- **Configuration Management**: Centralized configuration with environment variable support

## Prerequisites

- Python 3.7+
- Flask and required dependencies (see requirements below)

## Installation

1. **Clone or download the project files**:
   ```bash
   # Ensure you have these files:
   # - HTTP_Dashboard.py
   # - templates/admin_login.html
   # - templates/admin_panel.html
   # - static/admin_panel.js
   ```

2. **Install required dependencies**:
   ```bash
   pip install flask werkzeug requests python-dotenv waitress
   or
   pip install -r requirements.txt
   ```

3. **Set up environment variables** (optional but recommended):
   ```bash
   # Create a .env file in the project directory
   ADMIN_USERNAME=your_admin_username
   ADMIN_PASSWORD=your_secure_password
   TELEGRAM_BOT_TOKEN=your_telegram_bot_token
   TELEGRAM_CHAT_ID=your_telegram_chat_id
   ```

4. **Create required directories**:
   ```bash
   mkdir -p Database templates static uploads
   ```

## Configuration

The application uses a configuration file (`config.ini`) that's automatically created on first run. You can customize:

### Server Settings
- `port`: Server port (default: 1000)
- `max_content_length`: Maximum file upload size (default: 64MB)
- `session_timeout`: Session timeout in seconds (default: 1800)

### Database Settings
- `records_db`: Path to POST requests database
- `other_db`: Path to other requests database
- `journal_mode`: SQLite journal mode (default: WAL)

### Storage Settings
- `upload_folder`: Directory for uploaded files
- `allowed_extensions`: Allowed file extensions

### Authentication
- `admin_username`: Admin username
- `admin_password`: Admin password (hashed)
- `max_login_attempts`: Maximum login attempts before lockout
- `lockout_time`: Lockout duration in seconds

### Telegram Integration
- `bot_token`: Telegram bot token
- `chat_id`: Telegram chat ID
- `api_timeout`: API request timeout

## Usage

### Starting the Application

```bash
python HTTP_Dashboard.py
```

The application will start on `http://localhost:1000` by default.

### Accessing the Admin Dashboard

1. Navigate to `http://localhost:1000/admin`
2. Use the configured admin credentials to log in
3. Access the admin panel to manage requests and files

### API Endpoints

- `GET/POST /`: Main endpoint that logs all requests
- `GET /admin`: Admin login page
- `GET /admin/panel`: Admin dashboard (requires authentication)
- `POST /upload`: File upload endpoint
- `GET /files`: List uploaded files
- `GET /files/<filename>`: Serve uploaded files
- `GET /health`: Health check endpoint

### Admin Features

- **View Statistics**: See counts of logged requests and uploaded files
- **Send to Telegram**: Send logged data to configured Telegram chat
- **Clear Records**: Delete all logged requests
- **Download CSV**: Export logged data to CSV format
- **File Management**: View, download, and delete uploaded files

## Security Features

- **Authentication**: HTTP Basic Auth and session-based authentication
- **Rate Limiting**: Protection against brute force attacks
- **CSRF Protection**: Cross-site request forgery protection
- **Input Validation**: File upload validation and secure filename handling
- **SQL Injection Prevention**: Parameterized queries
- **Security Headers**: Comprehensive security headers on all responses
- **Secure Configuration**: Proper file permissions and secure defaults

## Database Schema

The application uses two SQLite databases:

### Records Database (`records.db`)
Stores POST requests:
```sql
CREATE TABLE records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    body TEXT,
    headers TEXT,
    user_agent TEXT
);
```

### Other Database (`other.db`)
Stores non-POST requests with the same schema.

## File Structure

```
project/
├── HTTP_Dashboard.py          # Main application file
├── config.ini                 # Configuration file (auto-generated)
├── .env                      # Environment variables (optional)
├── templates/
│   ├── admin_login.html      # Admin login template
│   └── admin_panel.html      # Admin dashboard template
├── static/
│   └── admin_panel.js        # Admin panel JavaScript
├── Database/
│   ├── records.db            # POST requests database
│   └── other.db              # Other requests database
├── uploads/                  # Uploaded files directory
└── app.log                   # Application log file
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_USERNAME` | Admin username | `admin` |
| `ADMIN_PASSWORD` | Admin password | `password` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | None |
| `TELEGRAM_CHAT_ID` | Telegram chat ID | None |

## Logging

The application logs to both console and file (`app.log`). Log levels include:
- `INFO`: General application information
- `WARNING`: Security events and warnings
- `ERROR`: Application errors
- `CRITICAL`: Fatal errors

## Telegram Integration

To enable Telegram integration:

1. Create a Telegram bot using [@BotFather](https://t.me/botfather)
2. Get your chat ID (you can use [@userinfobot](https://t.me/userinfobot))
3. Set the `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` environment variables
4. Use the "Send to Telegram" buttons in the admin panel

## Security Considerations

- Change default admin credentials immediately
- Use HTTPS in production
- Regularly backup databases
- Monitor log files for suspicious activity
- Keep dependencies updated
- Configure firewall rules appropriately

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure the application has write permissions to the Database and uploads directories
2. **Port Already in Use**: Change the port in `config.ini` or stop the conflicting service
3. **Database Locked**: Stop the application and restart it
4. **Telegram Not Working**: Verify bot token and chat ID are correct

### Debug Mode

To enable debug logging, modify the logging level in the code:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is provided as-is. Please review and test thoroughly before using in production environments.

## Support

For issues and questions:
1. Check the application logs (`app.log`)
2. Verify configuration settings
3. Review the troubleshooting section
4. Check file permissions and directory structure

# User Authentication and Authorization System

A secure PHP-based user management system with registration, login, password recovery, and role-based access control.

## Features

- User registration with secure password hashing
- User login with session management
- Role-based access control (Admin and User roles)
- Password recovery system with email verification
- Secure password requirements
- Session timeout and security
- Responsive Bootstrap UI

## Requirements

- PHP 7.4 or higher
- MySQL 5.7 or higher
- Web server (Apache/Nginx)
- PHP extensions: mysqli, session

## Installation

1. Clone or download this repository to your web server directory
2. Create a MySQL database named `user_management`
3. Import the `database.sql` file to create the necessary tables
4. Configure the database connection in `config.php`:
   ```php
   define('DB_HOST', 'localhost');
   define('DB_USER', 'your_username');
   define('DB_PASS', 'your_password');
   define('DB_NAME', 'user_management');
   ```
5. Make sure your web server has write permissions for the session directory

## Default Admin Account

- Username: admin
- Password: Admin@123

## Security Features

- Password hashing using PHP's password_hash()
- Prepared statements to prevent SQL injection
- Input sanitization
- Session management
- Password strength requirements
- Secure password reset tokens
- Role-based access control

## File Structure

- `config.php` - Database configuration and common functions
- `register.php` - User registration
- `login.php` - User login
- `dashboard.php` - User dashboard with role-based content
- `logout.php` - Session destruction
- `forgot_password.php` - Password recovery request
- `reset_password.php` - Password reset form
- `database.sql` - Database schema and initial data

## Usage

1. Access the system through your web browser
2. Register a new account or login with the default admin account
3. Admins can access the admin panel with additional features
4. Users can update their profile and change their password

## Security Best Practices

- Always use HTTPS in production
- Keep PHP and MySQL updated
- Regularly backup your database
- Monitor system logs for suspicious activity
- Implement rate limiting for login attempts
- Use strong passwords and encourage users to do the same

## License

This project is open-source and available under the MIT License. #   U s e r - A u t h e n t i c a t i o n - a n d - A u t h o r i z a t i o n - S y s t e m  
 
import logging
import logging.handlers
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
import socketserver
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from influxdb_client import InfluxDBClient, Point


'''influxdb_url = 'http://localhost:8086'
influxdb_token = 'your-influxdb-token'
influxdb_org = 'your-org'
influxdb_bucket = 'your-bucket'
influxdb_client = InfluxDBClient(url=influxdb_url, token=influxdb_token)'''


app = Flask(__name__)
app.secret_key = 'justin'


def get_db_connection():
    conn = sqlite3.connect('syslog.db')
    conn.row_factory = sqlite3.Row
    return conn
def initialize_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                host TEXT,
                log TEXT,
                log_level TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password_hash TEXT,
                role TEXT
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelisted_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_pools (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_range TEXT UNIQUE
            )
        ''')
        conn.commit()

initialize_db()

def create_default_users():
    admin_username = 'root'
    admin_password = 'Admin@9889#'
    user_username = 'adminuser'
    user_password = 'useradmin348$'

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (admin_username,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                           (admin_username, generate_password_hash(admin_password), 'admin'))
            conn.commit()

        cursor.execute('SELECT * FROM users WHERE username = ?', (user_username,))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                           (user_username, generate_password_hash(user_password), 'user'))
            conn.commit()

create_default_users()

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip())
        socket = self.request[1]
        host = self.client_address[0]
        print(f"{host} : {data}")

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM whitelisted_ips WHERE ip_address = ?', (host,))
            whitelisted_ip = cursor.fetchone()

            if not whitelisted_ip:
                print(f"IP {host} is not whitelisted. Log not saved.")
                return  

        log_level = 'INFO'
        if 'error' in data.lower():
            log_level = 'ERROR'
        elif 'warning' in data.lower():
            log_level = 'WARNING'
        elif 'debug' in data.lower():
            log_level = 'DEBUG'
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO logs (timestamp, host, log, log_level) VALUES (?, ?, ?, ?)",
                           (timestamp, host, data, log_level))
            conn.commit()


def setup_logger():
    logger = logging.getLogger('SyslogServer')
    logger.setLevel(logging.INFO)
    return logger

logger = setup_logger()

def login_required(f):
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

def role_required(role):
    def decorator(f):
        def wrap(*args, **kwargs):
            if 'logged_in' not in session:
                return redirect(url_for('login'))
            if session.get('role') != role:
                return render_template('404.html')
            return f(*args, **kwargs)
        wrap.__name__ = f.__name__
        return wrap
    return decorator

def prune_old_logs():
    cutoff_date = datetime.now() - timedelta(days=3*30)  # Approximate 3 months as 90 days
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM logs WHERE timestamp < ?', (cutoff_date,))
        conn.commit()
    print(f"Pruned logs older than {cutoff_date}")

'''def write_log_to_influxdb(host, log, log_level):
    write_api = influxdb_client.write_api()
    point = Point("logs") \
        .tag("host", host) \
        .field("log", log) \
        .field("log_level", log_level)
    write_api.write(bucket=influxdb_bucket, org=influxdb_org, record=point)

def handle(self):
    data = bytes.decode(self.request[0].strip())
    socket = self.request[1]
    host = self.client_address[0]
    print(f"{host} : {data}")

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM whitelisted_ips WHERE ip_address = ?', (host,))
        whitelisted_ip = cursor.fetchone()

        if not whitelisted_ip:
            print(f"IP {host} is not whitelisted. Log not saved.")
            return  

    log_level = 'INFO'
    if 'error' in data.lower():
        log_level = 'ERROR'
    elif 'warning' in data.lower():
        log_level = 'WARNING'
    elif 'debug' in data.lower():
        log_level = 'DEBUG'

    # Write to InfluxDB
    write_log_to_influxdb(host, data, log_level)'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password_hash'], password):
                session['logged_in'] = True
                session['username'] = username
                session['role'] = user['role']
                return redirect(url_for('index'))
            else:
                return render_template('404.html')
    return render_template('kvlogin.html')
@app.route('/login1')
def login1():
    return render_template('kvlogin.html')

@app.route('/logout')

def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    start_timestamp = request.args.get('start_timestamp')
    end_timestamp = request.args.get('end_timestamp')
    host = request.args.get('host')
    search_term = request.args.get('search_term')
    page = int(request.args.get('page', 1))
    per_page = 50

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if start_timestamp:
        query += " AND timestamp >= ?"
        params.append(start_timestamp)

    if end_timestamp:
        query += " AND timestamp <= ?"
        params.append(end_timestamp)

    if host:
        query += " AND host = ?"
        params.append(host)

    if search_term:
        query += " AND log LIKE ?"
        params.append(f'%{search_term}%')
    query += " ORDER BY timestamp DESC"
    offset = (page - 1) * per_page
    query += f" LIMIT ? OFFSET ?"
    params.extend([per_page, offset])
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        logs = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]

    total_pages = (total_logs + per_page - 1) // per_page

    return render_template('index.html', logs=logs, start_timestamp=start_timestamp, end_timestamp=end_timestamp, host=host, search_term=search_term, page=page, total_pages=total_pages)

@app.route('/prune_logs', methods=['POST'])
@login_required
@role_required('admin')
def prune_logs():
    prune_old_logs()
    return 'Old logs pruned!'

@app.route('/view_logs', methods=['GET'])
@login_required
def view_logs():
    page = request.args.get('page', 1, type=int)  
    per_page = 20 

    start_timestamp = request.args.get('start_timestamp')
    end_timestamp = request.args.get('end_timestamp')
    host = request.args.get('host')
    search_term = request.args.get('search_term')

    query = "SELECT * FROM logs WHERE 1=1"
    params = []

    if start_timestamp:
        query += " AND timestamp >= ?"
        params.append(start_timestamp)

    if end_timestamp:
        query += " AND timestamp <= ?"
        params.append(end_timestamp)

    if host:
        query += " AND host = ?"
        params.append(host)

    query_count = "SELECT COUNT(*) FROM logs WHERE 1=1"
    query_count += "".join([" AND timestamp >= ?", " AND timestamp <= ?", " AND host = ?"][:len(params)])
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query_count, params)
        total_logs = cursor.fetchone()[0]
        
        total_pages = (total_logs + per_page - 1) // per_page  # Calculate total number of pages
        offset = (page - 1) * per_page  # Calculate the offset for the current page
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(query, params)
        logs = cursor.fetchall()

    start_page = max(1, page - 2)  
    end_page = min(total_pages, page + 2) 
    if total_pages > 5:
        if end_page - start_page < 4:
            if start_page == 1:
                end_page = min(5, total_pages)
            else:
                start_page = max(1, total_pages - 4)

    return render_template('view_logs.html', logs=logs, start_timestamp=start_timestamp, end_timestamp=end_timestamp, host=host, search_term=search_term, page=page, total_pages=total_pages, start_page=start_page, end_page=end_page)

@app.route('/clear')
@login_required
@role_required('admin')
def clear_logs():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM logs")
        conn.commit()
    return 'Logs cleared!'

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def admin():
    if request.method == 'POST':
        if 'add_whitelisted_ip' in request.form:
            ip_address = request.form['ip_address']
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR IGNORE INTO whitelisted_ips (ip_address) VALUES (?)', (ip_address,))
                conn.commit()
        elif 'remove_whitelisted_ip' in request.form:
            ip_id = request.form['ip_id']
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM whitelisted_ips WHERE id = ?', (ip_id,))
                conn.commit()
        elif 'add_ip_pool' in request.form:
            ip_range = request.form['ip_range']
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('INSERT OR IGNORE INTO ip_pools (ip_range) VALUES (?)', (ip_range,))
                conn.commit()
        elif 'remove_ip_pool' in request.form:
            pool_id = request.form['pool_id']
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM ip_pools WHERE id = ?', (pool_id,))
                conn.commit()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM whitelisted_ips')
        whitelisted_ips = cursor.fetchall()

        cursor.execute('SELECT * FROM ip_pools')
        ip_pools = cursor.fetchall()

    return render_template('admin.html', whitelisted_ips=whitelisted_ips, ip_pools=ip_pools)

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 514
    server = socketserver.UDPServer((HOST, PORT), SyslogUDPHandler)

    # Start Flask app in a separate thread
    import threading
    flask_thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 8080})
    flask_thread.start()

    print(f"Starting syslog server on {HOST}:{PORT}")
    server.serve_forever()

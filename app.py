from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

# Conectar ao banco de dados SQLite


def get_db_connection():
    conn = sqlite3.connect('cimas_maker.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar o banco de dados


def init_db():
    with app.app_context():
        db = get_db_connection()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                profile TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                description TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
        ''')
        db.commit()

# Rota inicial


@app.route('/')
def index():
    return render_template('index.html')

# Rota de registro de usuários


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        profile = request.form['profile']

        db = get_db_connection()
        try:
            db.execute('INSERT INTO users (name, email, password, profile) VALUES (?, ?, ?, ?)',
                       (name, email, password, profile))
            db.commit()
            flash('Usuário cadastrado com sucesso!')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('E-mail já cadastrado.')
        finally:
            db.close()
    return render_template('register.html')

# Rota de login


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        db = get_db_connection()
        user = db.execute(
            'SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        db.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['profile'] = user['profile']
            return redirect(url_for('dashboard'))
        else:
            flash('Login inválido. Verifique suas credenciais.')

    return render_template('login.html')

# Rota de dashboard


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', profile=session['profile'])

# Rota para upload de arquivos


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        description = request.form['description']
        if file:
            file_path = f'uploads/{file.filename}'
            file.save(file_path)

            db = get_db_connection()
            db.execute('INSERT INTO uploads (user_id, file_name, file_path, description) VALUES (?, ?, ?, ?)',
                       (session['user_id'], file.filename, file_path, description))
            db.commit()
            db.close()
            flash('Arquivo enviado com sucesso!')
            return redirect(url_for('dashboard'))

    return render_template('upload.html')

# Rota para logout

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
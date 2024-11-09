from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import os



app = Flask(__name__)
app.secret_key = 'sua_chave_secreta'

# Configurações do Flask-Mail para Hotmail
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'adrilysilva8@gmail.com'
app.config['MAIL_PASSWORD'] = 'escola2015@'  # Sua senha do email
app.config['MAIL_DEFAULT_SENDER'] = 'adrilysilva8@gmail.com'
mail = Mail(app)

# Gerador de tokens seguros
s = URLSafeTimedSerializer(app.secret_key)

# Extensões de arquivo permitidas para upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx'}

# Função para verificar extensões permitidas
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL
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
        password = request.form['password']
        profile = request.form['profile']

        # Verifica se a senha tem pelo menos 8 caracteres
        if len(password) < 8:
            flash('A senha deve ter pelo menos 8 caracteres.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        db = get_db_connection()
        try:
            db.execute('INSERT INTO users (name, email, password, profile) VALUES (?, ?, ?, ?)',
                       (name, email, hashed_password, profile))
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
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        db.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['profile'] = user['profile']
            return redirect(url_for('dashboard'))
        else:
            flash('Login inválido, verifique suas credenciais.')

    return render_template('login.html')

# Rota de solicitação de redefinição de senha
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']

        db = get_db_connection()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        db.close()

        if user:
            token = s.dumps(email, salt='password-reset-salt')
            link = url_for('reset_password', token=token, _external=True)

            # Enviar o email com o link de redefinição
            msg = Message('Redefinir Senha', recipients=[email])
            msg.body = f'Clique no link para redefinir sua senha: {link}'
            mail.send(msg)

            flash('Instruções para redefinir a senha foram enviadas para o seu email.')
            return redirect(url_for('login'))
        else:
            flash('Email não encontrado.')
            return redirect(url_for('reset_password_request'))

    return render_template('reset_password_request.html')

# Rota para redefinir senha
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)  # 1 hora de validade
    except SignatureExpired:
        flash('O link de redefinição de senha expirou.')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        new_password = request.form['password']

        # Verifica se a nova senha tem pelo menos 8 caracteres
        if len(new_password) < 8:
            flash('A nova senha deve ter pelo menos 8 caracteres.')
            return redirect(url_for('reset_password', token=token))

        hashed_password = generate_password_hash(new_password)

        db = get_db_connection()
        db.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
        db.commit()
        db.close()

        flash('Sua senha foi redefinida com sucesso!')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

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
        if file and allowed_file(file.filename):
            file_path = f'uploads/{file.filename}'
            file.save(file_path)

            db = get_db_connection()
            db.execute('INSERT INTO uploads (user_id, file_name, file_path, description) VALUES (?, ?, ?, ?)',
                       (session['user_id'], file.filename, file_path, description))
            db.commit()
            db.close()
            flash('Arquivo enviado com sucesso!')
            return redirect(url_for('dashboard'))
        else:
            flash('Tipo de arquivo não permitido ou nenhum arquivo selecionado.')
            return redirect(url_for('upload'))

    return render_template('upload.html')

# Rota para logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Rota para funcionalidades do administrador
@app.route('/admin_features')
def admin_features():
    if 'user_id' not in session or session['profile'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_features.html')

# Rota para funcionalidades do professor
@app.route('/teacher_features')
def teacher_features():
    if 'user_id' not in session or session['profile'] != 'teacher':
        return redirect(url_for('login'))
    return render_template('teacher_features.html')

# Rota para funcionalidades do aluno
@app.route('/student_features')
def student_features():
    if 'user_id' not in session or session['profile'] != 'student':
        return redirect(url_for('login'))
    return render_template('student_features.html')

# Rota para feedback
@app.route('/feedback', methods=['POST'])
def feedback():
    user_feedback = request.form['feedback']
    
    if not user_feedback:
        flash('Por favor, forneça um feedback.')
        return redirect(url_for('index'))

    try:
        db = get_db_connection()
        db.execute('INSERT INTO feedback (content) VALUES (?)', (user_feedback,))
        db.commit()
        db.close()

        flash('Obrigado pelo seu feedback!')
    except sqlite3.Error as e:
        flash(f'Ocorreu um erro ao salvar seu feedback: {e}')
    
    return redirect(url_for('index'))

# Rota para o chatbot
@app.route('/chatbot')
def chatbot():
    
        
    return render_template('chatbot.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
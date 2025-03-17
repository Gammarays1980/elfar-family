from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, send
from flask_uploads import UploadSet, configure_uploads, IMAGES
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'your_secret_key'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elfar_family.db'
    app.config['UPLOADED_PHOTOS_DEST'] = 'static/uploads'

    # Initialize extensions
    bcrypt = Bcrypt(app)
    db = SQLAlchemy(app)
    login_manager = LoginManager(app)
    login_manager.login_view = 'login'
    socketio = SocketIO(app)
    photos = UploadSet('photos', IMAGES)
    configure_uploads(app, photos)

    # User model
    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password = db.Column(db.String(120), nullable=False)

    # Task model
    class Task(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.String(100), nullable=False)
        assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
        status = db.Column(db.String(20), default='Pending')

    # Photo model
    class Photo(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        filename = db.Column(db.String(120), nullable=False)
        uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))

    # Load user for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Helper function to check file extensions
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

    # Routes
    @app.route('/')
    def home():
        if current_user.is_authenticated:
            # Fetch photos uploaded by all family members
            family_photos = Photo.query.all()
            photos_with_uploader = []
            for photo in family_photos:
                uploader = User.query.get(photo.uploaded_by)  # Fetch the user who uploaded the photo
                photos_with_uploader.append({
                    'filename': photo.filename,
                    'uploader': uploader.username  # Use the username of the uploader
                })

            # Fetch recent activity (example: last 5 photos uploaded)
            recent_activity = [f"New photo uploaded by {photo['uploader']}" for photo in photos_with_uploader[:5]]
        else:
            photos_with_uploader = []
            recent_activity = []

        return render_template('index.html', photos_with_uploader=photos_with_uploader, recent_activity=recent_activity)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('home'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        return render_template('register.html')

    @app.route('/files', methods=['GET', 'POST'])
    @login_required
    def files():
        if request.method == 'POST' and 'photo' in request.files:
            file = request.files['photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOADED_PHOTOS_DEST'], filename))
                
                # Save photo info to the database
                new_photo = Photo(filename=filename, uploaded_by=current_user.id)
                db.session.add(new_photo)
                db.session.commit()
                
                flash(f"File {filename} uploaded!")
            else:
                flash('Invalid file type. Allowed types are: png, jpg, jpeg, gif.')
        # Fetch photos uploaded by all family members
        family_photos = Photo.query.all()
        photos_with_uploader = []
        for photo in family_photos:
            uploader = User.query.get(photo.uploaded_by)
            photos_with_uploader.append({
                'filename': photo.filename,
                'uploader': uploader.username
            })
        return render_template('files.html', photos_with_uploader=photos_with_uploader)

    @app.route('/tasks', methods=['GET', 'POST'])
    @login_required
    def tasks():
        if request.method == 'POST':
            title = request.form['title']
            new_task = Task(title=title, assigned_to=current_user.id)
            db.session.add(new_task)
            db.session.commit()
            flash('Task added!')
        tasks = Task.query.filter_by(assigned_to=current_user.id).all()
        return render_template('tasks.html', tasks=tasks)

    @app.route('/complete_task/<int:task_id>')
    @login_required
    def complete_task(task_id):
        task = Task.query.get(task_id)
        if task and task.assigned_to == current_user.id:
            task.status = 'Completed'
            db.session.commit()
            flash('Task marked as completed!')
        return redirect(url_for('tasks'))

    @app.route('/delete_task/<int:task_id>')
    @login_required
    def delete_task(task_id):
        task = Task.query.get(task_id)
        if task and task.assigned_to == current_user.id:
            db.session.delete(task)
            db.session.commit()
            flash('Task deleted!')
        return redirect(url_for('tasks'))

    # Chat Route
    @app.route('/chat')
    @login_required
    def chat():
        return render_template('chat.html')

    # SocketIO event
    @socketio.on('message')
    def handle_message(msg):
        if current_user.is_authenticated:
            send({'username': current_user.username, 'message': msg}, broadcast=True)
        else:
            send({'username': 'Anonymous', 'message': msg}, broadcast=True)

    # Create database tables
    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    socketio.run(app, debug=True)
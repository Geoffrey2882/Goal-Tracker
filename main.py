from flask import Flask, render_template, request, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, current_user, logout_user
from werkzeug.security import check_password_hash
from flask_wtf import FlaskForm
from wtforms import  StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure random key

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)


#Registration
class RegistrationForm(FlaskForm):
  username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
  #email = StringField('Email', validators=[DataRequired(), Email()])
  password = PasswordField('Password', validators=[DataRequired()])
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  submit = SubmitField('Sign Up')

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100), unique=True, nullable=False)
  password = db.Column(db.String(100), nullable=False)

class RegistrationForm(FlaskForm):
  username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
  password = PasswordField('Password', validators=[DataRequired()])
  confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
  submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
  username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
  password = PasswordField('Password', validators=[DataRequired()])
  submit = SubmitField('Sign in')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))


# Goal model
class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    goal_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(200), nullable=False)
    skill = db.Column(db.String(200), nullable=False)
    time_limit = db.Column(db.String(200), nullable=False)
    #is_completed = db.Column(db.Boolean, default=False)
    #user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
  username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
  password = PasswordField('Password', validators=[DataRequired()])
  submit = SubmitField('Sign in')

@app.route('/')
@login_required
def home():
    goals = Goal.query.all()
    return render_template('home.html', goals=goals)

@app.route('/addskill', methods=['GET','POST'])
def add_skill():
    if request.method == 'POST':
        # Retrieve form data
        goal_name = request.form.get('goal')
        category = request.form.get('category')
        skill = request.form.get('skill')
        time_limit = request.form.get('time_limit')

        # Process the form data (e.g., add to the database)
        # Example: Creating a new skill object (adjust per your schema)
        new_skill = Goal(goal_name=goal_name, category=category, skill=skill, time_limit=time_limit)
        db.session.add(new_skill)
        db.session.commit()

        # Redirect to the home page or any desired page after adding the skill
        return redirect(url_for('home'))

    # Handle other cases (GET request or form submission failure)
    # You might want to flash a message or handle errors here
    return render_template('newskill.html')


@app.route('/updateskill', methods=['GET', 'POST'])
def update_skill():
    if request.method == 'POST':
        goal_id = request.form.get('goal')
        time_used = request.form.get('time_used')
        progress_description = request.form.get('progress_description')

        # Find the goal by its id
        goal = Goal.query.get(goal_id)

        if goal:
            goal.time_used = time_used  # Update the time used for the goal
            goal.progress_description = progress_description  # Update the progress description for the goal
            db.session.commit()  # Commit the changes to the database

            # Redirect to the home page with the updated goals
            goals = Goal.query.all()
            return render_template('home.html', goals=goals)
    else:
        goals = Goal.query.all()
        return render_template('updateskill.html', goals=goals)


@app.route('/deletegoal/<int:goal_id>', methods=['POST'])
def delete_goal(goal_id):
    goal_to_delete = Goal.query.get_or_404(goal_id)
    db.session.delete(goal_to_delete)
    db.session.commit()
    return redirect('/')


if __name__ == '__main__':
  with app.app_context():
    db.drop_all()
    db.create_all()  # Create tables based on defined models
  app.run(host='0.0.0.0', port=5000, debug=True)

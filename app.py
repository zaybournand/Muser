from flask import Flask, url_for, request, redirect, render_template, flash
from flask_migrate import Migrate 
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from datetime import datetime
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(120), nullable=False)

class Opportunity(db.Model):
    __tablename__ = 'opportunities'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(120), nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    professional_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    professional = db.relationship('User', backref='posted_opportunities', lazy=True)

    def __repr__(self):
        return f"<Opportunity {self.title}, posted by {self.professional_id}>"

class Application(db.Model):
    __tablename__ = 'applications'

    id = db.Column(db.Integer, primary_key=True)
    opportunity_id = db.Column(db.Integer, db.ForeignKey('opportunities.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default="Pending")

    opportunity = db.relationship('Opportunity', backref='applications', lazy=True)
    student = db.relationship('User', backref='applied_opportunities', lazy=True)

    def __repr__(self):
        return f"<Application by User {self.student_id} for Opportunity {self.opportunity_id} with status {self.status}>"


@app.route('/application_status/<int:id>', methods=['GET', 'POST'])
@login_required
def status(id):
    application_status = Application.query.get_or_404(id)
    if application_status.professional_id != current_user.id:
        flash("You are not authorized to edit this opportunity.", "danger")
        return redirect(url_for('index'))
    if request.method == 'POST':
        application_status.status = request.form['status']
        try:
            db.session.commit()
            flash("Application status updated successfully!.", "danger")
            return redirect(url_for('view_applications', opportunity_id=application_status.opportunity_id))
        except Exception as e:
            flash(f"There was an error changing application status: {e}", "danger")
            return redirect('/')
    return render_template('application_status.html', application=application_status)

@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def profile_update():
    user_update = User.query.get_or_404(current_user.id) 
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        user_type = request.form['user_type']

      
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('profile_update'))

        if password:
            user_update.password = generate_password_hash(password) 
        
        user_update.username = username
        user_update.email = email
        user_update.user_type = user_type

        try:
            db.session.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))  
        
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('profile_update'))

    return render_template('profile.html', user=user_update)  

@app.route('/search_opportunities', methods=['GET', 'POST'])
@login_required
def search_opportunities():
    keyword = request.args.get('keyword')  
    location = request.args.get('location')  
    
    
    query = Opportunity.query
    if keyword:
        query = query.filter(Opportunity.title.like(f'%{keyword}%') | Opportunity.description.like(f'%{keyword}%'))
    if location:
        query = query.filter(Opportunity.location.like(f'%{location}%'))
    
    opportunities = query.all()  

    return render_template('search_results.html', opportunities=opportunities, keyword=keyword, location=location)

@app.route('/apply', methods=['POST'])
@login_required
def apply():
    opportunity_id = request.form['opportunity_id']
    if current_user.user_type != 'student':
        flash("Only students can apply for opportunities.", "danger")
        return redirect(url_for('view_opportunities'))
    
    existing_application = Application.query.filter_by(opportunity_id=opportunity_id, student_id=current_user.id).first()
    if existing_application:
        flash("You have already applied for this opportunity.", "warning")
        return redirect(url_for('view_opportunities'))
    new_application = Application(opportunity_id=opportunity_id,student_id=current_user.id)

    try:
        db.session.add(new_application)
        db.session.commit()
        flash("Application successfully submitted!", "success")
        return redirect(url_for('view_opportunities'))
        
    except Exception as e:
        flash(f"There was an error applying: {e}", "danger")
        return redirect('view_opportunities')
    
@app.route('/view_applications/<int:opportunity_id>', methods=['GET'])
@login_required
def view_application(opportunity_id):
    opportunity = Opportunity.query.get_or_404(opportunity_id)
    
    if opportunity.professional_id != current_user.id:
        flash("You are not authorized to view applications.", "danger")
        return redirect(url_for('index'))
    
    applications = Application.query.filter_by(opportunity_id=opportunity_id).all()
    students = [User.query.get(app.student_id) for app in applications]

    return render_template('application.html', applications=applications, opportunity=opportunity, students=students)



@app.route('/add_opportunity', methods=['POST'])
@login_required
def add_opportunity(id):
    title = request.form['title']
    description = request.form['description']
    location = request.form['location']
    
    
    new_opportunitiy = Opportunity(title=title, description=description, location=location,  professional_id=current_user.id )
    try:
        db.session.add(new_opportunitiy)
        db.session.commit()
        flash("Opportunity added successfully!", "success")
        return redirect('/')
    
    except Exception as e:
        flash(f"There was an error creating opportunity: {e}", "danger")
        return redirect('/')

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    opportunity_to_delete = Opportunity.query.get_or_404(id)
    if opportunity_to_delete.professional_id != current_user.id:
        flash("You are not authorized to delete this opportunity.", "danger")
        return redirect(url_for('index'))
    try:
        db.session.delete(opportunity_to_delete)
        db.session.commit()
        flash("Opportunity deleted successfully!", "success")
        return redirect('/')
    except Exception as e:
        flash(f"There was an error deleting the opportunity: {e}", "danger")
        return redirect('/')
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    opportunity_to_edit = Opportunity.query.get_or_404(id)

    
    if opportunity_to_edit.professional_id != current_user.id:
        flash("You are not authorized to edit this opportunity.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
       
        opportunity_to_edit.title = request.form['title']
        opportunity_to_edit.description = request.form['description']
        opportunity_to_edit.location = request.form['location']

        try:
            db.session.commit()
            flash("Opportunity updated successfully!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            flash(f"There was an error updating the opportunity: {e}", "danger")
            return redirect(url_for('index'))

    
    return render_template('edit_opportunity.html', opportunity=opportunity_to_edit)


@app.route('/view_opportunity', methods=['GET'])
@login_required
def view_opportunity():
    opportunities = Opportunity.query.all()

    return render_template('opportunities.html', opportunities=opportunities)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        user_type = request.form['user_type']

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash("Email already exists. Please login or use another email.", "danger")
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, user_type=user_type)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for('login'))
        
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('index'))
        else:
            flash("Login failed. Check your email and password.", "danger")

    return render_template('login.html')

@app.route('/', methods=['GET'])
@login_required
def index():
    return render_template('index.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have successfully logged out.", "info")
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)

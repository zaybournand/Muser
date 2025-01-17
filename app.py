from flask import Flask, url_for, request, redirect, render_template, flash
from flask_migrate import Migrate 
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin, login_required
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired
from flask_bcrypt import Bcrypt


app = Flask(__name__)


@app.route('/')
def index():
    return 'Hello world'

if __name__ == "__main__":
    app.run(debug=True)

from flask_login import LoginManager
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session

app = Flask(__name__)


db = SQLAlchemy()

def create_app():
    app.secret_key = 'Kf}>NPGv2er<;P,z?U8x01}c'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://manii:password@localhost/shift_updates_db'
    db.init_app(app)

    # this is needed in order for database session calls (e.g. db.session.commit)
    with app.app_context():
#      try:
      db.create_all()
#      except Exception as exception:
#          print("got the following exception when attempting db.create_all() in __init__.py: " + str(exception))
#      finally:
#          print("db.create_all() in __init__.py was successfull - no exceptions were raised")

    return app

from flask_migrate import Migrate

migrate = Migrate(app, db)
from app.models import User
from app.routes import app, db


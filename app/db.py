from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.secret_key = 'Kf}>NPGv2er<;P,z?U8x01}c'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://manii:password@localhost/shift_updates_db'  # Use your database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

DATABASE_URI = 'mysql+pymysql://manii:password@localhost/shift_updates_db'

engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

db = SQLAlchemy()


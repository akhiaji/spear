from app import db


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password = db.Column(db.String(120), index=True, unique=True)
    files = db.relationship('File', backref='owner', lazy='dynamic')


    def __repr__(self):
        return '<User %r>' % (self.username)

class File(db.Model):
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(64), index = True)
	parent = db.Column(db.String(64), index = True)
	content_path = db.Column(db.String(64), index = True)
	dropbox = db.Column(db.Boolean, index = True)
	folder = db.Column(db.Boolean)
	last_updated = db.Column(db.DateTime)

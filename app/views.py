import sqlite3
import json
import httplib2
import pickle
import os
#import memcache
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash,_app_ctx_stack

from flask.ext.sqlalchemy import SQLAlchemy
from contextlib import closing
from oauth2client.client import OAuth2WebServerFlow, OAuth2Credentials
from dropbox.client import DropboxClient, DropboxOAuth2Flow
from googleapiclient.discovery import build
from datetime import timedelta, datetime
from app import app
from config import DROPBOX_APP_KEY, DROPBOX_APP_SECRET
from config import GDRIVE_CLIENT_ID, GDRIVE_CLIENT_SECRET, GDRIVE_SCOPE, GDRIVE_REDIRECT_URI
from config import USER_SCHEMA, FILE_SCHEMA
from models import User

def get_auth_flow():
    redirect_uri = url_for('dropbox_auth_finish', _external=True)
    return DropboxOAuth2Flow(DROPBOX_APP_KEY, DROPBOX_APP_SECRET, redirect_uri,
                                       session, 'dropbox-auth-csrf-token')

def get_gd_auth_flow():
    redirect_uri = url_for('google_auth_finish', _external = True)
    return OAuth2WebServerFlow(client_id=GDRIVE_CLIENT_ID,
                           client_secret=GDRIVE_CLIENT_SECRET,
                           scope = GDRIVE_SCOPE,
                           redirect_uri=GDRIVE_REDIRECT_URI,
                           access_type = 'offline')

def valid_user(s):
    cur = list(g.db.execute('SELECT username from users order by id desc' ))
    entries = []
    for row in cur:
        entries.append(row[0]) 
    return s in entries

def valid_pswd(usr, pswd):
    cur = list(g.db.execute('SELECT username, password from users WHERE username = ? order by id desc', [usr]))
    return str(cur[0][1]) == pswd

def get_user(s):
    account = {}
    cur = list(g.db.execute('SELECT * from users  WHERE username = ? order by id desc', [s]))
    if len(cur) > 0:
        for idx, item in enumerate(cur[0]):
            account[USER_SCHEMA[idx]]= item
    return account

def get_file(content_path, owner):
    account = {}
    cur = list(g.db.execute('SELECT * from file Where owner = ? and content_path = ?', [owner, content_path]))
    if len(cur) > 0:
        for idx, item in enumerate(cur[0]):
            account[FILE_SCHEMA[idx]]= item
    return account

@app.route('/dropbox-auth-start')
def dropbox_auth_start():
    if 'user' not in session:
        abort(403)
    return redirect(get_auth_flow().start())

@app.route('/google-auth-start')
def google_auth_start():
    if 'user' not in session:
        abort(403)
    return redirect(get_gd_auth_flow().step1_get_authorize_url())

@app.route('/dropbox-auth-finish')
def dropbox_auth_finish():
    username = session.get('user')
    if username is None:
        abort(403)
    try:
        access_token, user_id, url_state = get_auth_flow().finish(request.args)
    except DropboxOAuth2Flow.BadRequestException, e:
        abort(400)
    except DropboxOAuth2Flow.BadStateException, e:
        abort(400)
    except DropboxOAuth2Flow.CsrfException, e:
        abort(403)
    except DropboxOAuth2Flow.NotApprovedException, e:
        flash('Not approved?  Why not')
        return redirect(url_for('home'))
    except DropboxOAuth2Flow.ProviderException, e:
        app.logger.exception("Auth error" + e)
        abort(403)
    data = [access_token, session['user']]
    g.db.execute('UPDATE users SET db_access_token = ? WHERE username = ?', data)
    g.db.execute('INSERT or REPLACE into file (ID, owner, name, parent, content_path, dropbox, folder) values ((SELECT ID FROM file WHERE content_path = ?),?,?,?,?,?,?)', [ 'None', username, 'dropbox', 'None', '/', True, True])
    g.db.commit()
    return redirect(url_for('accounts'))

@app.route('/google-auth-finish')
def google_auth_finish():
    username = session.get('user')
    if username is None:
        abort(403)
    code = request.args.get('code')
    access_credential = get_gd_auth_flow().step2_exchange(code)
    g.db.execute('UPDATE users SET gd_access_token = ? WHERE username = ?', [pickle.dumps(access_credential), username])
    g.db.execute('INSERT or REPLACE into file (ID, owner, name, parent, content_path, dropbox, folder) values ((SELECT ID FROM file WHERE content_path = ?),?,?,?,?,?,?)', [ 'None', username, 'google', 'None', 'root', False, True])
    g.db.commit()
    return redirect(url_for('accounts'))


@app.route('/dropbox-logout')
def dropbox_logout():
    username = session.get('user')
    if username is None:
        abort(403)
    g.db.execute('UPDATE users SET db_access_token = NULL WHERE username = ?', [username])
    g.db.commit()
    return redirect(url_for('accounts'))

@app.route('/google-logout')
def google_logout():
    username = session.get('user')
    if username is None:
        abort(403)
    g.db.execute('UPDATE users SET gd_access_token = NULL WHERE username = ?', [username])
    g.db.commit()
    return redirect(url_for('accounts'))

def connect_db():
    return sqlite3.connect(app.config['DATABASE'])

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

@app.route('/login', methods = ['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not valid_user(username):
            error = 'Invalid Username'
        elif not valid_pswd(username, password):
            error = 'Invalid Password'
        else:
            session['user'] = username
            flash('You were logged in')
            return redirect(url_for('accounts'))
    return render_template('login.html', error = error)


@app.route('/signup', methods = ['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        verify = request.form['verify']
        if valid_user(username):
            error = 'Name already exists'
        elif password != verify:
            error = 'passwords do not match'
        else:
            session['user'] = username
            g.db.execute('INSERT into users (username, password) values (?,?)', [username, password])
            g.db.commit()
            return redirect(url_for('accounts'))
    return render_template('signup.html', error = error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You were logged out')
    return redirect(url_for('login'))

@app.route('/accounts', methods = ['GET', 'POST'])
def accounts():
    if not session.get('user'):
         abort(401)
    if request.method == 'POST':
        if request.form.get('db_in') == "Log In":
            return redirect(url_for('dropbox_auth_start')) 
        elif request.form.get('db_in') == "Log Out":
            return redirect(url_for('dropbox_logout'))
        if request.form.get('gd_in') == "Log In":
            return redirect(url_for('google_auth_start'))
        elif request.form.get('gd_in') == "Log Out":
            return redirect(url_for('google_logout'))
    account = get_user(session.get('user'))
    accounts = {}
    if not account.get("db_access_token") is None:
        accounts['dropbox'] = True
    if not account.get("gd_access_token") is None:
        accounts['google'] = True
    return render_template('accounts.html', accounts = accounts)

@app.route('/show-files')
def show_files():
    return render_template('show_files.html')

@app.route('/get-files')
def get_files():
    a = request.args.get('path', None, type=str)
    b = str(request.args.get('type', None))
    file_list = []
    if not a is None:
        if a == '/':
            for item in json.loads(dropbox_files(a)):
                file_list.append((item[2], item[4], item[5], item[6], item[0]))
            for item in json.loads(google_files('root')):        
                file_list.append((item[2], item[4], item[5], item[6], item[0]))
            return json.dumps(file_list)
        elif a == 'root':
            for item in json.loads(dropbox_files('/')):
                file_list.append((item[2], item[4], item[5], item[6], item[0]))
            for item in json.loads(google_files(a)):        
                file_list.append((item[2], item[4], item[5], item[6], item[0]))
            return json.dumps(file_list)
        if b.isdigit() and int(b) == 1:       
            print json.loads(dropbox_files(a))
            for item in json.loads(dropbox_files(a)):
                file_list.append((item[2], item[4], item[5], item[6], item[0]))
        else:
            for item in json.loads(google_files(a)):        
                file_list.append((item[2], item[4], item[5], item[6], item[0]))
        return json.dumps(file_list)



@app.route('/get-parent')
def get_parent():
    a = request.args.get('path', None, type=str)
    b = str(request.args.get('type', None)) 
    print a
    print b
    if not a is None:
        if b.isdigit() and int(b) == 1 and a != '/':
            return json.dumps([os.path.dirname(a),1])
        elif a == '/':
            return json.dumps(['/',1])
        elif a == 'root':
            return json.dumps(['root',0])
        else:
            if not session.get('user'):
                abort(401)
            user = get_user(session.get('user'))
            cur = list(g.db.execute("SELECT parent from file WHERE content_path = ? and owner = ?", [a,user.get("username")]))
            return json.dumps([cur[0][0],0])

def dropbox_files(path):
    if not session.get('user'):
        abort(401)
    user = get_user(session.get('user'))
    if user.get('db_access_token') is None:
        abort(401)
    opening_file = get_file(path, user.get("username"))
    if (not opening_file.get('last_updated') is None):
        if (datetime.now()- datetime.strptime(str(opening_file['last_updated'])[:18], "%Y-%m-%dT%H:%M:%S")).seconds<3600:
            cur2 = list(g.db.execute('SELECT * from file WHERE parent = ? and owner = ? and dropbox = ?', [path, user.get("username"), True]))
            return json.dumps(cur2)
   
    db_token = user['db_access_token']
    client = DropboxClient(db_token)
    print "DB API REQUEST"
    metadata = client.metadata(path)
    for contents in metadata['contents']:
        title = contents['path'][contents['path'].rfind('/')+1:]
        g.db.execute('INSERT or REPLACE into file (ID, owner, name, parent, content_path, dropbox, folder) values ((SELECT ID FROM file WHERE content_path = ?and owner = ?),?,?,?,?,?,?)', [ contents['path'], user.get("username"), user.get("username"), title, path, contents['path'], True, contents['is_dir']])
    g.db.execute('UPDATE file SET last_updated = ? WHERE owner = ? and content_path = ?', [str(datetime.now().isoformat()), user.get("username"), path])
    g.db.commit()
    cur3 = list(g.db.execute('SELECT * from file WHERE owner = ? and parent = ? and dropbox = ?', [user.get("username"), path, True]))
    return json.dumps(cur3)
    
def google_files(path):
    if not session.get('user'):
        abort(401)
    user = get_user(session.get('user'))
    if user.get('gd_access_token') is None:
        abort(401)
    opening_file = get_file(path, user.get("username"))
    if (not opening_file.get('last_updated') is None):
        if (datetime.now()- datetime.strptime(str(opening_file['last_updated'])[:18], "%Y-%m-%dT%H:%M:%S")).seconds<3600:
            cur2 = list(g.db.execute('SELECT * from file WHERE parent = ? and owner = ? and dropbox = ? ', [path, user.get('username'), False]))
            return json.dumps(cur2)
    g.db.execute('UPDATE file SET last_updated = ? WHERE owner = ? and content_path = ?', [str(datetime.now().isoformat()), user.get("username"), path])
    g.db.commit()
    credential = user['gd_access_token']
    credential = pickle.loads(credential)
    http = httplib2.Http()
    if credential.access_token_expired:
        credential.refresh(http)
    http = httplib2.Http()
    http = credential.authorize(http)
    drive_service = build('drive', 'v2', http = http)
    results =  drive_service.children().list(folderId = path).execute()
    print "Google API REQUEST"
    for child in results.get('items', []):
        metadata = drive_service.files().get(fileId = child['id']).execute()
        folder = metadata.get('mimeType') == 'application/vnd.google-apps.folder'
        g.db.execute('INSERT or REPLACE into file (ID, owner, name, parent, content_path, dropbox, folder) values ((SELECT ID FROM file WHERE content_path = ? and owner = ?),?,?,?,?,?,?)', [ metadata.get('id'), user.get("username"), user.get("username"), metadata.get('title'), path, metadata.get('id'), False, folder]) 
    g.db.execute('UPDATE file SET last_updated = ? WHERE owner = ? and content_path = ?', [str(datetime.now().isoformat()), user.get("username"), path])
    g.db.commit()
    cur3 = list(g.db.execute('SELECT * from file WHERE owner = ? and parent = ? and dropbox = ?', [user.get("username"), path, False]))
    return json.dumps(cur3)



    #changes = drive_service.changes().list(startChangeId = opening_file.get('last_updated'), includeDeleted = False).execute()
    # g.db.execute('UPDATE file SET last_updated = ? WHERE owner = ? and content_path = ?', [changes.get('largestChangeId'), user.get("username"), path])
    # print changes.get('items')[0]
    # for item in changes.get('items'):
    #     print item.get('fileId')
    #     metadata = item.get('file')
    #     folder = metadata.get('mimeType') == 'application/vnd.google-apps.folder'
    #     g.db.execute('INSERT or REPLACE into file (ID, owner, name, parent, content_path, dropbox, folder) values ((SELECT ID FROM file WHERE content_path = ? and owner = ?),?,?,?,?,?,?)', [ metadata.get('id'), user.get("username"), user.get("username"), metadata.get('title'), path, metadata.get('id'), False, folder]) 
    # if (not opening_file.get('last_updated') is None):

    #     if (datetime.now()- datetime.strptime(str(opening_file['last_updated'])[:18], "%Y-%m-%dT%H:%M:%S")).seconds<3600:
    #         cur2 = list(g.db.execute('SELECT * from file WHERE parent = ? and owner = ? and dropbox = ? ', [path, user.get('username'), False]))
    #         return json.dumps(cur2)
    # g.db.execute('UPDATE file SET last_updated = ? WHERE owner = ? and content_path = ?', [str(datetime.now().isoformat()), user.get("username"), path])
    # credential = user['gd_access_token']
    # http = httplib2.Http()
    # credential = pickle.loads(credential)
    # if credential.access_token_expired:
    #     a = credential.refresh(http)
    #     print "expiration"
    #     print a
    #     g.db.execute('UPDATE users SET gd_access_token = ? WHERE username = ?', [pickle.dumps(credential), username])

    # http = httplib2.Http()
    # http = credential.authorize(http)
    # drive_service = build('drive', 'v2', http = http)
    # if not session.get('changeId') == None:
    #     changes = drive_service.changes().list(startChangeId = session.get('changeId')).execute()
    #     print "changes1"
    #     for a in range(0, len(changes.get('items'))):
    #         print changes.get('items')[a].get('fileId')
    #         print (drive_service.files().get(fileId = changes.get('items')[a].get('fileId')).execute()).get('title')
    #     session['changeId'] = changes['largestChangeId']
    # else:
    #     changes = drive_service.changes().list().execute()
    #     print "changes"
    #     print changes['largestChangeId']
    #     session['changeId'] = changes['largestChangeId']

    # results =  drive_service.children().list(folderId = path).execute()
    # print "Google API REQUEST"
    # for child in results.get('items', []):
    #     metadata = drive_service.files().get(fileId = child['id']).execute()
    #     folder = metadata.get('mimeType') == 'application/vnd.google-apps.folder'
    #     g.db.execute('INSERT or REPLACE into file (ID, owner, name, parent, content_path, dropbox, folder) values ((SELECT ID FROM file WHERE content_path = ? and owner = ?),?,?,?,?,?,?)', [ metadata.get('id'), user.get("username"), user.get("username"), metadata.get('title'), path, metadata.get('id'), False, folder]) 
    # g.db.execute('UPDATE file SET last_updated = ? WHERE owner = ? and content_path = ?', [str(datetime.now().isoformat()), user.get("username"), path])
    g.db.commit()
    cur3 = list(g.db.execute('SELECT * from file WHERE owner = ? and parent = ? and dropbox = ?', [user.get("username"), path, False]))
    return json.dumps(cur3)
        


 
if __name__ == '__main__':
    app.run()


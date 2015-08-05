DATABASE = '/tmp/spear.db'
DEBUG = True
SECRET_KEY = 'development key'
DROPBOX_APP_KEY = '1szh06pzua9nm1a'
DROPBOX_APP_SECRET = '4pqoe16cl3jtctf'

GDRIVE_CLIENT_ID='384706005510-hbbdfl1tef8g06artuuft5ubc7a9fllp.apps.googleusercontent.com'
GDRIVE_CLIENT_SECRET='RyYaHJkGL_Q9rYeqcjIylbHO'
GDRIVE_REDIRECT_URI = 'http://127.0.0.1:5000/google-auth-finish'
GDRIVE_SCOPE="https://www.googleapis.com/auth/drive"

USER_SCHEMA = ("id", "username", "password", "db_access_token", "gd_access_token")
FILE_SCHEMA = ("id", "owner", "name", "parent", "content_path", "dropbox", "folder", "last_updated")
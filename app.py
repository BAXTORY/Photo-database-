
import os
import uuid
import hmac
from functools import wraps
from flask import (
    Flask, request, redirect, url_for,
    session, flash, render_template_string,
    abort
)
from supabase import create_client


# ---------------- CONFIGURATION ----------------

app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["MAX_CONTENT_LENGTH"] = 110 * 1024 * 1024

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

BUCKET = "private-photos"
MAX_FILE_SIZE = 10 * 1024 * 1024
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# ---------------- SECURITY ----------------

def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def get_csrf_token():
    import secrets
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = get_csrf_token


def verify_csrf():
    submitted = request.form.get("csrf_token", "")
    saved = session.get("csrf_token", "")

    if not saved or not hmac.compare_digest(submitted, saved):
        abort(400, "Invalid security token. Please refresh the page.")


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ---------------- HTML DESIGN ----------------

STYLE = """
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #090d18;
    color: #f4f6ff;
    font-family: Arial, sans-serif;
}
.container {
    max-width: 1100px;
    margin: auto;
    padding: 25px 18px;
}
header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    margin-bottom: 30px;
}
.logo {
    font-size: 23px;
    font-weight: bold;
    color: #9b8cff;
}
.card {
    background: #141b2c;
    border: 1px solid #273149;
    border-radius: 18px;
    padding: 22px;
    margin-bottom: 22px;
}
input, button {
    width: 100%;
    padding: 14px;
    border-radius: 10px;
    border: 1px solid #35415b;
    background: #0d1423;
    color: white;
    margin-top: 10px;
    font-size: 15px;
}
button {
    background: #7258ee;
    border: none;
    font-weight: bold;
    cursor: pointer;
}
button:hover { background: #876fff; }
a { color: #b5a8ff; text-decoration: none; }
.small-btn {
    display: inline-block;
    padding: 9px 13px;
    border-radius: 8px;
    background: #273149;
    margin-top: 8px;
}
.logout { width: auto; padding: 10px 15px; }
.grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(190px, 1fr));
    gap: 17px;
}
.photo {
    background: #141b2c;
    border: 1px solid #273149;
    padding: 10px;
    border-radius: 14px;
    min-width: 0;
}
.photo img {
    width: 100%;
    height: 180px;
    object-fit: cover;
    border-radius: 9px;
    background: #080c15;
}
.filename {
    font-size: 12px;
    color: #aab3c8;
    overflow-wrap: anywhere;
    margin-top: 10px;
}
.delete-btn { background: #b93650; }
.message {
    background: #202b43;
    padding: 12px;
    border-radius: 9px;
    margin-bottom: 12px;
}
.muted { color: #9ca9c1; }
.login-box {
    max-width: 410px;
    margin: 10vh auto;
}
h1 { font-size: 28px; }
</style>
"""


LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Private Photos - Login</title>
""" + STYLE + """
</head>
<body>
<div class="container">
    <div class="login-box card">
        <div class="logo">✦ Private Photos</div>
        <h1>Welcome back</h1>
        <p class="muted">Sign in to access your private gallery.</p>

        {% for message in get_flashed_messages() %}
            <div class="message">{{ message }}</div>
        {% endfor %}

        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <input name="username" placeholder="Username" required>
            <input name="password" type="password"
                   placeholder="Password" required>
            <button type="submit">Sign in</button>
        </form>
    </div>
</div>
</body>
</html>
"""


GALLERY_PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Private Photos</title>
""" + STYLE + """
</head>
<body>
<div class="container">

<header>
    <div class="logo">✦ Private Photos</div>
    <form method="POST" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button class="logout" type="submit">Logout</button>
    </form>
</header>

{% for message in get_flashed_messages() %}
    <div class="message">{{ message }}</div>
{% endfor %}

<div class="card">
    <h1>Your Gallery</h1>
    <p class="muted">{{ photos|length }} photo(s) stored</p>
</div>

<div class="card">
    <h2>Upload photos</h2>
    <p class="muted">JPG, JPEG, PNG, GIF and WEBP. Maximum 10 MB each.</p>

    <form method="POST" action="{{ url_for('upload') }}"
          enctype="multipart/form-data">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <input type="file" name="photos" accept="image/*" multiple required>
        <button type="submit">Upload photos</button>
    </form>
</div>

<h2>All photos</h2>

{% if photos %}
<div class="grid">
    {% for photo in photos %}
    <div class="photo">
        <a href="{{ url_for('download', filename=photo.name) }}">
            <img src="{{ photo.url }}" alt="Photo" loading="lazy">
        </a>

        <div class="filename">{{ photo.name }}</div>

        <a class="small-btn"
           href="{{ url_for('download', filename=photo.name) }}">
           View / Download
        </a>

        <form method="POST" action="{{ url_for('delete', filename=photo.name) }}"
              onsubmit="return confirm('Delete this photo?')">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <button class="delete-btn" type="submit">Delete</button>
        </form>
    </div>
    {% endfor %}
</div>
{% else %}
<div class="card">
    <p class="muted">Your gallery is empty. Upload your first photo above.</p>
</div>
{% endif %}

</div>
</body>
</html>
"""


# ---------------- LOGIN ----------------

@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("admin"):
        return redirect(url_for("gallery"))

    if request.method == "POST":
        verify_csrf()

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        correct_user = hmac.compare_digest(username, ADMIN_USERNAME)
        correct_pass = hmac.compare_digest(password, ADMIN_PASSWORD)

        if correct_user and correct_pass:
            session.clear()
            session["admin"] = True
            session.permanent = True
            flash("Login successful.")
            return redirect(url_for("gallery"))

        flash("Incorrect username or password.")

    return render_template_string(LOGIN_PAGE)


# ---------------- GALLERY ----------------

@app.route("/gallery")
@admin_required
def gallery():

    try:
        result = supabase.storage.from_(BUCKET).list()
        photos = []

        for item in result:
            name = item.get("name", "")

            if not name or not allowed_file(name):
                continue

            signed = supabase.storage.from_(BUCKET).create_signed_url(
                name, 3600
            )

            signed_url = signed.get("signedURL") or signed.get("signedUrl")

            if signed_url:
                photos.append({
                    "name": name,
                    "url": signed_url
                })

        photos.sort(key=lambda x: x["name"], reverse=True)

        return render_template_string(
            GALLERY_PAGE,
            photos=photos
        )

    except Exception:
        app.logger.exception("Gallery loading failed")
        return "Gallery could not be loaded. Check the Render logs.", 500


# ---------------- UPLOAD ----------------

@app.route("/upload", methods=["POST"])
@admin_required
def upload():

    verify_csrf()

    files = request.files.getlist("photos")

    if not files or all(not f.filename for f in files):
        flash("Please select at least one photo.")
        return redirect(url_for("gallery"))

    if len(files) > 10:
        flash("You can upload a maximum of 10 photos at once.")
        return redirect(url_for("gallery"))

    success = 0

    for file in files:

        if not file or not file.filename:
            continue

        if not allowed_file(file.filename):
            flash("An unsupported file type was skipped.")
            continue

        data = file.read()

        if len(data) > MAX_FILE_SIZE:
            flash("A photo larger than 10 MB was skipped.")
            continue

        extension = file.filename.rsplit(".", 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{extension}"

        content_types = {
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "webp": "image/webp"
        }

        try:
            supabase.storage.from_(BUCKET).upload(
                filename,
                data,
                file_options={
                    "content-type": content_types[extension],
                    "upsert": "false"
                }
            )
            success += 1

        except Exception:
            app.logger.exception("Photo upload failed")
            flash("One photo could not be uploaded.")

    if success:
        flash(f"{success} photo(s) uploaded successfully.")

    return redirect(url_for("gallery"))


# ---------------- DOWNLOAD ----------------

@app.route("/download/<filename>")
@admin_required
def download(filename):

    if not allowed_file(filename) or "/" in filename or "\\" in filename:
        abort(404)

    try:
        signed = supabase.storage.from_(BUCKET).create_signed_url(
            filename, 300
        )

        signed_url = signed.get("signedURL") or signed.get("signedUrl")

        if not signed_url:
            abort(404)

        return redirect(signed_url)

    except Exception:
        app.logger.exception("Download link creation failed")
        abort(404)


# ---------------- DELETE ----------------

@app.route("/delete/<filename>", methods=["POST"])
@admin_required
def delete(filename):

    verify_csrf()

    if not allowed_file(filename) or "/" in filename or "\\" in filename:
        abort(404)

    try:
        supabase.storage.from_(BUCKET).remove([filename])
        flash("Photo deleted successfully.")

    except Exception:
        app.logger.exception("Photo deletion failed")
        flash("Could not delete this photo.")

    return redirect(url_for("gallery"))


# ---------------- LOGOUT ----------------

@app.route("/logout", methods=["POST"])
@admin_required
def logout():

    verify_csrf()
    session.clear()
    return redirect(url_for("login"))


# ---------------- START ----------------

if __name__ == "__main__":
    app.run(debug=False)
            

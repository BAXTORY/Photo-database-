
import os
import uuid
import hmac
from functools import wraps
from io import BytesIO

import requests
from flask import (
    Flask, request, redirect, url_for,
    session, render_template_string, flash,
    send_file, abort
)
from supabase import create_client

app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

BUCKET = "private-photos"
MAX_FILE_SIZE = 10 * 1024 * 1024

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

ALLOWED = {"jpg", "jpeg", "png", "webp", "gif"}

PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>My Private Gallery</title>
<style>
* {box-sizing:border-box}
body {
    margin:0;
    padding:20px;
    background:#111827;
    color:white;
    font-family:Arial,sans-serif;
}
main {max-width:950px;margin:auto}
header {
    display:flex;
    justify-content:space-between;
    align-items:center;
    flex-wrap:wrap;
}
h1 {font-size:25px}
.panel {
    background:#253247;
    padding:20px;
    border-radius:14px;
    margin:20px 0;
}
input,button {
    padding:12px;
    border-radius:8px;
    margin:6px 0;
    max-width:100%;
}
input {background:#e5e7eb;color:#111827}
button {
    background:#2563eb;
    color:white;
    border:0;
    cursor:pointer;
}
a {color:#93c5fd;text-decoration:none}
.grid {
    display:grid;
    grid-template-columns:repeat(auto-fill,minmax(180px,1fr));
    gap:14px;
}
.photo {
    background:#253247;
    padding:10px;
    border-radius:12px;
}
.photo img {
    width:100%;
    height:170px;
    object-fit:cover;
    border-radius:8px;
}
.actions {
    display:flex;
    justify-content:space-between;
    align-items:center;
    gap:8px;
    flex-wrap:wrap;
}
.danger {background:#b91c1c}
.muted {color:#9ca3af}
.message {color:#86efac}
</style>
</head>
<body>
<main>

{% if logged_in %}

<header>
<h1>My Private Gallery</h1>
<a href="/logout">Log out</a>
</header>

<p class="muted">ADMIN DASHBOARD · PRIVATE STORAGE</p>

<div class="panel">
<h3>Upload Photos</h3>
<form action="/upload" method="POST" enctype="multipart/form-data">
<input type="file" name="photos" accept="image/*" multiple required>
<br>
<button type="submit">Upload Photos</button>
</form>
<p class="muted">Maximum 10 MB per photo.</p>
</div>

{% for message in messages %}
<p class="message">{{ message }}</p>
{% endfor %}

<h2>My Gallery</h2>

<div class="grid">
{% for photo in photos %}
<div class="photo">
<img src="{{ photo.url }}" alt="Private photo">
<div class="actions">
<a href="{{ photo.url }}" target="_blank">View</a>
<a href="{{ url_for('download', name=photo.name) }}">Download</a>
<form action="/delete" method="POST">
<input type="hidden" name="name" value="{{ photo.name }}">
<button class="danger">Delete</button>
</form>
</div>
</div>
{% else %}
<p class="muted">No photos uploaded yet.</p>
{% endfor %}
</div>

{% else %}

<div class="panel">
<h1>My Private Gallery</h1>
<p class="muted">ADMIN ACCESS ONLY</p>

<form method="POST" action="/login">
<input name="username" placeholder="Admin username" required>
<br>
<input name="password" type="password" placeholder="Password" required>
<br>
<button type="submit">Log in</button>
</form>

{% for message in messages %}
<p class="message">{{ message }}</p>
{% endfor %}
</div>

{% endif %}

</main>
</body>
</html>
"""


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def get_photo(name):
    if not name or "/" in name or "\\" in name:
        abort(404)

    try:
        result = supabase.storage.from_(BUCKET).create_signed_url(
            name, 3600
        )
        return result.get("signedURL") or result.get("signedUrl")
    except Exception:
        app.logger.exception("Could not create photo URL")
        return None


@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin"):
        return redirect(url_for("gallery"))

    messages = []

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_user = hmac.compare_digest(username, ADMIN_USERNAME)
        valid_pass = hmac.compare_digest(password, ADMIN_PASSWORD)

        if valid_user and valid_pass:
            session.clear()
            session["admin"] = True
            return redirect(url_for("gallery"))

        messages.append("Incorrect username or password.")

    return render_template_string(
        PAGE,
        logged_in=False,
        messages=messages,
        photos=[]
    )


@app.route("/gallery")
@admin_required
def gallery():
    try:
        result = supabase.storage.from_(BUCKET).list()
        photos = []

        for item in result:
            name = item.get("name")

            if not name:
                continue

            url = get_photo(name)

            if url:
                photos.append({
                    "name": name,
                    "url": url
                })

        photos.reverse()

        return render_template_string(
            PAGE,
            logged_in=True,
            photos=photos,
            messages=[]
        )

    except Exception as e:
        app.logger.exception("Gallery loading failed")
        return f"Gallery error: {type(e).__name__}", 500


@app.route("/upload", methods=["POST"])
@admin_required
def upload():
    files = request.files.getlist("photos")
    uploaded = 0

    for file in files:
        if not file or not file.filename:
            continue

        filename = file.filename

        if "." not in filename:
            continue

        extension = filename.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED:
            continue

        content = file.read()

        if not content or len(content) > MAX_FILE_SIZE:
            continue

        name = f"{uuid.uuid4().hex}.{extension}"

        try:
            supabase.storage.from_(BUCKET).upload(
                name,
                content,
                {
                    "content-type": file.mimetype or "application/octet-stream",
                    "upsert": "false"
                }
            )
            uploaded += 1

        except Exception:
            app.logger.exception("Photo upload failed")
            continue

    if uploaded:
        flash(f"{uploaded} photo(s) uploaded successfully.")
    else:
        flash("No photos were uploaded. Check file types and sizes.")

    return redirect(url_for("gallery"))


@app.route("/delete", methods=["POST"])
@admin_required
def delete():
    name = request.form.get("name", "")

    if not name or "/" in name or "\\" in name:
        abort(400)

    try:
        supabase.storage.from_(BUCKET).remove([name])
        flash("Photo deleted successfully.")
    except Exception:
        app.logger.exception("Photo deletion failed")
        flash("Could not delete photo.")

    return redirect(url_for("gallery"))


@app.route("/download/<name>")
@admin_required
def download(name):
    url = get_photo(name)

    if not url:
        abort(404)

    response = requests.get(url, timeout=30)

    if response.status_code != 200:
        abort(404)

    return send_file(
        BytesIO(response.content),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=name
    )


@app.route("/logout")
@admin_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(413)
def too_large(error):
    return "Upload too large. Reduce the total upload size.", 413


if __name__ == "__main__":
    app.run(debug=False)

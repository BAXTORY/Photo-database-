
import os
import uuid
import hmac
import secrets
import mimetypes
import requests

from io import BytesIO
from functools import wraps

from flask import (
    Flask, request, redirect, url_for,
    session, render_template_string, flash,
    send_file, abort, get_flashed_messages
)

from supabase import create_client


app = Flask(__name__)

app.secret_key = os.environ["FLASK_SECRET_KEY"]

app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 3600

SUPABASE_URL = os.environ["SUPABASE_URL"].rstrip("/")
SUPABASE_KEY = os.environ["SUPABASE_KEY"]

ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]

BUCKET = "private-photos"
MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED = {
    "jpg", "jpeg", "png", "webp", "gif"
}

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)


# -----------------------------
# CSRF PROTECTION
# -----------------------------

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


def verify_csrf():
    submitted = request.form.get("csrf_token", "")
    saved = session.get("csrf_token", "")

    if not saved or not hmac.compare_digest(submitted, saved):
        abort(400, description="Invalid security token.")


# -----------------------------
# HTML DESIGN
# -----------------------------

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Private Gallery</title>

<style>

:root {
    --bg: #090b12;
    --panel: #121622;
    --panel2: #191f2e;
    --border: #252d3e;
    --text: #f4f5fa;
    --muted: #929bad;
    --accent: #8b7cff;
    --accent2: #5d8cff;
    --danger: #f05d73;
}

* {
    box-sizing: border-box;
}

body {
    margin: 0;
    min-height: 100vh;
    background:
        radial-gradient(ellipse at 15% 0%, #29204b 0%, transparent 35%),
        radial-gradient(ellipse at 90% 20%, #172c4c 0%, transparent 35%),
        var(--bg);
    color: var(--text);
    font-family: Inter, Arial, sans-serif;
}

button, input {
    font: inherit;
}

button {
    cursor: pointer;
}

a {
    color: inherit;
    text-decoration: none;
}

.container {
    max-width: 1150px;
    margin: auto;
    padding: 24px;
}

/* HEADER */

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 15px;
    padding: 15px 0 28px;
}

.brand {
    display: flex;
    align-items: center;
    gap: 12px;
}

.logo {
    width: 45px;
    height: 45px;
    border-radius: 14px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg, #8b7cff, #527dff);
    font-size: 23px;
    box-shadow: 0 8px 25px #6755ff55;
}

.brand h2 {
    font-size: 18px;
    margin: 0;
}

.brand small {
    color: var(--muted);
    font-size: 11px;
}

.logout {
    padding: 10px 16px;
    border: 1px solid var(--border);
    border-radius: 10px;
    color: #e5e7eb;
    background: #ffffff08;
    font-size: 13px;
}

/* INTRO */

.intro {
    margin: 25px 0;
}

.intro h1 {
    font-size: clamp(27px, 5vw, 38px);
    margin: 0 0 10px;
    letter-spacing: -1px;
}

.intro p {
    color: var(--muted);
    margin: 0;
    font-size: 14px;
}

/* STATISTICS */

.stats {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 15px;
    margin: 25px 0;
}

.stat {
    background: linear-gradient(145deg, #1c2232, #111622);
    border: 1px solid var(--border);
    padding: 20px;
    border-radius: 17px;
}

.stat-icon {
    font-size: 23px;
}

.stat h2 {
    font-size: 28px;
    margin: 12px 0 5px;
}

.stat p {
    color: var(--muted);
    font-size: 12px;
    margin: 0;
}

/* PANELS */

.panel {
    background: #141a27e8;
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 22px;
    margin: 20px 0;
}

.panel h3 {
    margin: 0 0 8px;
    font-size: 17px;
}

.muted {
    color: var(--muted);
    font-size: 13px;
}

/* UPLOAD */

.upload-area {
    border: 1.5px dashed #55517e;
    border-radius: 15px;
    background: #8b7cff08;
    padding: 30px 15px;
    text-align: center;
    transition: .2s;
}

.upload-area.dragover {
    background: #8b7cff22;
    border-color: var(--accent);
}

.upload-icon {
    font-size: 38px;
    margin-bottom: 12px;
}

.upload-area h3 {
    margin: 0 0 8px;
}

.upload-area p {
    color: var(--muted);
    font-size: 12px;
}

.file-input {
    display: none;
}

.primary-btn {
    display: inline-block;
    background: linear-gradient(135deg, #8b7cff, #557eff);
    color: white;
    border: 0;
    padding: 12px 22px;
    border-radius: 10px;
    font-weight: 600;
    margin-top: 12px;
    box-shadow: 0 7px 20px #655cff30;
}

.primary-btn:hover {
    opacity: .9;
}

.file-name {
    color: #a99fff;
    margin-top: 12px;
    font-size: 12px;
}

/* GALLERY */

.gallery-heading {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
    margin: 35px 0 18px;
}

.gallery-heading h2 {
    margin: 0;
    font-size: 21px;
}

.gallery-count {
    color: var(--muted);
    font-size: 12px;
}

.grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 16px;
}

.photo {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 15px;
    padding: 9px;
    overflow: hidden;
    transition: transform .2s, border-color .2s;
}

.photo:hover {
    transform: translateY(-4px);
    border-color: #7770b9;
}

.photo-img {
    width: 100%;
    aspect-ratio: 1 / 1;
    object-fit: cover;
    border-radius: 10px;
    display: block;
    background: #20283a;
    cursor: pointer;
}

.photo-actions {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 5px;
    margin-top: 10px;
}

.photo-actions a,
.photo-actions button {
    font-size: 11px;
    padding: 8px 9px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: #ffffff08;
    color: #dbe1ef;
}

.photo-actions .delete {
    color: #ff8191;
    border-color: #793747;
}

.photo-actions form {
    margin: 0;
}

/* EMPTY STATE */

.empty {
    text-align: center;
    padding: 55px 15px;
    border: 1px dashed var(--border);
    border-radius: 17px;
    color: var(--muted);
}

.empty div {
    font-size: 45px;
    margin-bottom: 12px;
}

/* MESSAGES */

.message {
    padding: 13px 15px;
    background: #172d27;
    border: 1px solid #28634a;
    color: #8df0bd;
    border-radius: 10px;
    font-size: 13px;
    margin: 12px 0;
}

.error-message {
    background: #351c29;
    border-color: #793747;
    color: #ff9baa;
}

/* PREVIEW MODAL */

.modal {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 100;
    background: #000e;
    justify-content: center;
    align-items: center;
    padding: 20px;
}

.modal.show {
    display: flex;
}

.modal-content {
    max-width: 900px;
    max-height: 90vh;
    position: relative;
}

.modal-content img {
    max-width: 100%;
    max-height: 85vh;
    object-fit: contain;
    border-radius: 12px;
}

.close-modal {
    position: absolute;
    right: 0;
    top: -42px;
    background: #252b3a;
    color: white;
    border: 0;
    border-radius: 50%;
    width: 35px;
    height: 35px;
    font-size: 20px;
}

/* LOGIN */

.login-wrap {
    min-height: 90vh;
    display: flex;
    justify-content: center;
    align-items: center;
}

.login-card {
    width: 100%;
    max-width: 410px;
    background: #151b29ed;
    border: 1px solid var(--border);
    padding: 32px;
    border-radius: 22px;
    box-shadow: 0 25px 80px #0007;
}

.login-card .logo {
    margin-bottom: 25px;
}

.login-card h1 {
    font-size: 27px;
    margin: 0 0 8px;
}

.login-card p {
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 25px;
}

.login-card input {
    width: 100%;
    padding: 14px;
    margin: 8px 0;
    background: #0c111d;
    border: 1px solid var(--border);
    border-radius: 10px;
    color: white;
    outline: none;
}

.login-card input:focus {
    border-color: var(--accent);
}

.login-card button {
    width: 100%;
    margin-top: 15px;
}

.footer {
    text-align: center;
    color: #687287;
    font-size: 11px;
    padding: 35px 0 15px;
}

@media(max-width: 700px) {
    .container {
        padding: 17px;
    }

    .grid {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: 11px;
    }

    .photo {
        padding: 7px;
    }

    .photo-actions a,
    .photo-actions button {
        padding: 7px 6px;
        font-size: 10px;
    }

    .panel {
        padding: 16px;
    }
}

@media(max-width: 350px) {
    .grid {
        grid-template-columns: 1fr;
    }
}

</style>
</head>

<body>

<div class="container">

{% if logged_in %}

<header class="header">

    <div class="brand">
        <div class="logo">✦</div>
        <div>
            <h2>Private Gallery</h2>
            <small>YOUR PERSONAL SPACE</small>
        </div>
    </div>

    <form action="/logout" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button class="logout" type="submit">Log out ↗</button>
    </form>

</header>

<section class="intro">
    <h1>Your memories,<br>beautifully stored.</h1>
    <p>Welcome to your private photo collection.</p>
</section>

<section class="stats">

    <div class="stat">
        <div class="stat-icon">▧</div>
        <h2>{{ total_photos }}</h2>
        <p>Total photos</p>
    </div>

    <div class="stat">
        <div class="stat-icon">🔒</div>
        <h2>Private</h2>
        <p>Storage protection</p>
    </div>

</section>

{% for category, message in messages %}
    <div class="message {% if category == 'error' %}error-message{% endif %}">
        {{ message }}
    </div>
{% endfor %}

<section class="panel">

    <h3>Upload new photos</h3>
    <p class="muted">Add your favourite moments to your collection.</p>

    <form action="/upload" method="POST"
          enctype="multipart/form-data" id="uploadForm">

        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

        <div class="upload-area" id="dropArea">

            <div class="upload-icon">☁</div>

            <h3>Drop your photos here</h3>

            <p>JPG, PNG, WEBP or GIF · Maximum 10 MB per photo</p>

            <label for="photos" class="primary-btn">
                Choose photos
            </label>

            <input
                class="file-input"
                type="file"
                id="photos"
                name="photos"
                accept=".jpg,.jpeg,.png,.webp,.gif"
                multiple
                required
            >

            <div class="file-name" id="fileName"></div>

        </div>

        <button type="submit" class="primary-btn">
            Upload photos ↑
        </button>

    </form>

</section>

<div class="gallery-heading">

    <h2>Your gallery</h2>

    <span class="gallery-count">
        {{ total_photos }} photos
    </span>

</div>

{% if photos %}

<div class="grid">

{% for photo in photos %}

    <div class="photo">

        <img
            class="photo-img"
            src="{{ photo.url }}"
            alt="Private photo"
            loading="lazy"
            onclick="openPreview(this.src)"
        >

        <div class="photo-actions">

            <a href="{{ photo.url }}" target="_blank" rel="noopener">
                View ↗
            </a>

            <a href="{{ url_for('download', name=photo.name) }}">
                Download ↓
            </a>

            <form action="/delete" method="POST"
                  onsubmit="return confirm('Delete this photo permanently?')">

                <input type="hidden" name="csrf_token"
                       value="{{ csrf_token() }}">

                <input type="hidden" name="name"
                       value="{{ photo.name }}">

                <button class="delete" type="submit">
                    Delete
                </button>

            </form>

        </div>

    </div>

{% endfor %}

</div>

{% else %}

<div class="empty">
    <div>▧</div>
    <h3>Your gallery is empty</h3>
    <p>Upload your first photo to get started.</p>
</div>

{% endif %}

<div class="footer">
    PRIVATE GALLERY · SECURE PHOTO STORAGE
</div>

{% else %}

<div class="login-wrap">

    <div class="login-card">

        <div class="logo">✦</div>

        <h1>Welcome back.</h1>

        <p>Sign in to access your private photo gallery.</p>

        {% for category, message in messages %}
            <div class="message error-message">
                {{ message }}
            </div>
        {% endfor %}

        <form action="/login" method="POST">

            <input type="hidden" name="csrf_token"
                   value="{{ csrf_token() }}">

            <input
                type="text"
                name="username"
                placeholder="Admin username"
                autocomplete="username"
                required
            >

            <input
                type="password"
                name="password"
                placeholder="Password"
                autocomplete="current-password"
                required
            >

            <button type="submit" class="primary-btn">
                Enter gallery →
            </button>

        </form>

        <div class="footer">
            🔒 ADMIN ACCESS ONLY
        </div>

    </div>

</div>

{% endif %}

</div>

<div class="modal" id="previewModal"
     onclick="closePreview()">

    <div class="modal-content" onclick="event.stopPropagation()">

        <button class="close-modal"
                onclick="closePreview()">×</button>

        <img id="previewImage" src="" alt="Photo preview">

    </div>

</div>

<script>

// PHOTO PREVIEW

function openPreview(src) {
    document.getElementById("previewImage").src = src;
    document.getElementById("previewModal").classList.add("show");
}

function closePreview() {
    document.getElementById("previewModal").classList.remove("show");
}


// FILE SELECTION

const fileInput = document.getElementById("photos");
const fileName = document.getElementById("fileName");
const dropArea = document.getElementById("dropArea");

if (fileInput) {

    fileInput.addEventListener("change", function() {

        if (this.files.length > 0) {
            fileName.textContent =
                this.files.length + " photo(s) selected";
        } else {
            fileName.textContent = "";
        }

    });

}


// DRAG AND DROP

if (dropArea && fileInput) {

    dropArea.addEventListener("dragover", function(e) {
        e.preventDefault();
        dropArea.classList.add("dragover");
    });

    dropArea.addEventListener("dragleave", function() {
        dropArea.classList.remove("dragover");
    });

    dropArea.addEventListener("drop", function(e) {

        e.preventDefault();
        dropArea.classList.remove("dragover");

        if (e.dataTransfer.files.length > 0) {

            fileInput.files = e.dataTransfer.files;

            fileName.textContent =
                fileInput.files.length + " photo(s) selected";

        }

    });

}


// ESCAPE KEY

document.addEventListener("keydown", function(e) {

    if (e.key === "Escape") {
        closePreview();
    }

});

</script>

</body>
</html>
"""


# -----------------------------
# AUTHENTICATION
# -----------------------------

def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin"):
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# -----------------------------
# PHOTO URL
# -----------------------------

def get_photo(name):

    if not name or "/" in name or "\\" in name:
        return None

    try:

        result = supabase.storage.from_(BUCKET).create_signed_url(
            name, 3600
        )

        return result.get("signedURL") or result.get("signedUrl")

    except Exception:

        app.logger.exception("Could not create signed URL")

        return None


# -----------------------------
# LOGIN
# -----------------------------

@app.route("/", methods=["GET"])
@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("admin"):
        return redirect(url_for("gallery"))

    if request.method == "POST":

        verify_csrf()

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_user = hmac.compare_digest(
            username, ADMIN_USERNAME
        )

        valid_pass = hmac.compare_digest(
            password, ADMIN_PASSWORD
        )

        if valid_user and valid_pass:

            session.clear()
            session["admin"] = True
            session.permanent = True

            return redirect(url_for("gallery"))

        flash("Incorrect username or password.", "error")

    return render_template_string(
        PAGE,
        logged_in=False,
        photos=[],
        total_photos=0,
        messages=get_flashed_messages(with_categories=True)
    )


# -----------------------------
# GALLERY
# -----------------------------

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

            extension = name.rsplit(".", 1)[-1].lower()

            if extension not in ALLOWED:
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
            total_photos=len(photos),
            messages=get_flashed_messages(with_categories=True)
        )

    except Exception as e:

        app.logger.exception("Gallery loading failed")

        return f"Gallery error: {str(e)}", 500


# -----------------------------
# UPLOAD
# -----------------------------

@app.route("/upload", methods=["POST"])
@admin_required
def upload():

    verify_csrf()

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

        content = file.read(MAX_FILE_SIZE + 1)

        if not content or len(content) > MAX_FILE_SIZE:
            continue

        name = f"{uuid.uuid4().hex}.{extension}"

        content_type = mimetypes.guess_type(
            "photo." + extension
        )[0] or "application/octet-stream"

        try:

            supabase.storage.from_(BUCKET).upload(
                name,
                content,
                {
                    "content-type": content_type,
                    "upsert": "false"
                }
            )

            uploaded += 1

        except Exception:

            app.logger.exception("Photo upload failed")

    if uploaded:
        flash(f"{uploaded} photo(s) uploaded successfully.", "success")
    else:
        flash("No photos uploaded. Check file types and sizes.", "error")

    return redirect(url_for("gallery"))


# -----------------------------
# DELETE
# -----------------------------

@app.route("/delete", methods=["POST"])
@admin_required
def delete():

    verify_csrf()

    name = request.form.get("name", "")

    if (
        not name
        or "/" in na

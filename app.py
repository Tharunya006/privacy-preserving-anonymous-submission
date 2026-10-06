from flask import Flask, render_template, request
import sqlite3
import os
import secrets
from werkzeug.utils import secure_filename

from metadata_scrubber import remove_metadata

app = Flask(__name__)

DATABASE = "database/app.db"


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/test-db")
def test_db():
    connection = get_db_connection()

    users = connection.execute(
        "SELECT * FROM users"
    ).fetchall()

    connection.close()

    return f"Database connected successfully! Users found: {len(users)}"


@app.route("/test-submissions")
def test_submissions():
    connection = get_db_connection()

    submissions = connection.execute(
        "SELECT * FROM submissions"
    ).fetchall()

    connection.close()

    result = "<h1>Submissions</h1>"

    for submission in submissions:
        result += f"""
        <p>
            <strong>ID:</strong> {submission['id']}<br>
            <strong>Token:</strong> {submission['submission_token']}<br>
            <strong>Title:</strong> {submission['title']}<br>
            <strong>Content:</strong> {submission['content']}<br>
            <strong>Status:</strong> {submission['status']}<br>
            <strong>Created At:</strong> {submission['created_at']}
        </p>
        <hr>
        """

    return result


@app.route("/submit", methods=["GET", "POST"])
def submit():

    if request.method == "POST":

        title = request.form["title"]
        content = request.form["content"]

        # Generate a secure random submission token
        submission_token = "SUB-" + secrets.token_hex(8).upper()

        # Create a private folder for this submission
        upload_folder = os.path.join(
            "uploads",
            submission_token
        )

        os.makedirs(upload_folder, exist_ok=True)

        # Get uploaded evidence file
        evidence = request.files.get("evidence")

        evidence_filename = None

        if evidence and evidence.filename:

            # Make the filename safe
            safe_filename = secure_filename(evidence.filename)

            # Allowed image extensions
            allowed_extensions = {
                ".jpg",
                ".jpeg",
                ".png",
                ".gif",
                ".webp"
            }

            file_extension = os.path.splitext(
                safe_filename
            )[1].lower()

            if file_extension not in allowed_extensions:
                return """
                <h1>Invalid Evidence File</h1>
                <p>Only image files are allowed.</p>
                <a href="/submit">Go Back</a>
                """

            # Create temporary path for the original uploaded image
            temp_path = os.path.join(
                upload_folder,
                "temp_" + safe_filename
            )

            # Final path for the cleaned image
            evidence_path = os.path.join(
                upload_folder,
                safe_filename
            )

            # Save original image temporarily
            evidence.save(temp_path)

            # Remove metadata and save the cleaned image
            remove_metadata(
                temp_path,
                evidence_path
            )

            # Delete the original image containing metadata
            os.remove(temp_path)

            evidence_filename = safe_filename

        # Store submission in SQLite
        connection = get_db_connection()

        connection.execute(
            """
            INSERT INTO submissions
            (submission_token, title, content, status)
            VALUES (?, ?, ?, ?)
            """,
            (
                submission_token,
                title,
                content,
                "Submitted"
            )
        )

        connection.commit()
        connection.close()

        return f"""
        <h1>Submission Received!</h1>

        <p>
            Your report has been submitted successfully.
        </p>

        <p>
            <strong>Submission Token:</strong>
            {submission_token}
        </p>

        <p>
            <strong>Status:</strong> Submitted
        </p>

        <p>
            Please save your submission token.
            You will need it to check your report status.
        </p>

        <br>

        <a href="/status">Check Submission Status</a>

        <br><br>

        <a href="/">Back to Home</a>
        """

    return render_template("submit.html")


@app.route("/status", methods=["GET", "POST"])
def status():

    if request.method == "POST":

        token = request.form["token"]

        connection = get_db_connection()

        submission = connection.execute(
            "SELECT * FROM submissions WHERE submission_token = ?",
            (token,)
        ).fetchone()

        connection.close()

        if submission:
            return f"""
            <h1>Submission Status</h1>

            <p>
                <strong>Token:</strong>
                {submission['submission_token']}
            </p>

            <p>
                <strong>Title:</strong>
                {submission['title']}
            </p>

            <p>
                <strong>Status:</strong>
                {submission['status']}
            </p>

            <p>
                <strong>Created At:</strong>
                {submission['created_at']}
            </p>

            <br>

            <a href="/">Back to Home</a>
            """

        return """
        <h1>Submission Not Found</h1>

        <p>No submission was found with this token.</p>

        <br>

        <a href="/status">Try Again</a>
        """

    return render_template("status.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        connection = get_db_connection()

        user = connection.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()

        connection.close()

        if user:
            return f"Login successful! Welcome {user['username']}."

        return "Invalid username or password."

    return render_template("login.html")


if __name__ == "__main__":
    app.run(debug=True)
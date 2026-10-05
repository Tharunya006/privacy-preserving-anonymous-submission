from flask import Flask, render_template, request
import sqlite3

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

        submission_token = "TOKEN-" + title.replace(" ", "-").upper()

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

        <p><strong>Title:</strong> {title}</p>

        <p><strong>Content:</strong> {content}</p>

        <p><strong>Submission Token:</strong> {submission_token}</p>

        <p><strong>Status:</strong> Submitted</p>

        <br>

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

            <p><strong>Token:</strong> {submission['submission_token']}</p>
            <p><strong>Title:</strong> {submission['title']}</p>
            <p><strong>Status:</strong> {submission['status']}</p>
            <p><strong>Created At:</strong> {submission['created_at']}</p>

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
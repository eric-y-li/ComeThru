import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///data.db")


@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/form", methods=["GET", "POST"])
@login_required
def form():
    """Get information for event"""
    if request.method == "POST":
        # Make sure they've clicked a host tag
        if not request.get.form("host"):
            return apology("Must select a host", 400)
        # Make sure they've entered an event name
        elif not request.get.form("eventName"):
            return apology("Must enter event name", 400)
        # Make sure they've entered description
        elif not request.get.form("description"):
            return apology("Must enter a description", 400)
        # Check for start time
        elif not request.get.form("starttime"):
            return apology("Must enter a start time", 400)
        # Check for endtime
        elif not request.get.form("endtime"):
            return apology("Must enter an end time", 400)
        # Check for address
        elif not request.get.form("address"):
            return apology("Must enter an event address", 400)
        # Insert input from form into database
        db.execute("INSERT INTO events (eventname, starttime, endtime, description, eventhost, latitude, longitude, address) VALUES (:eventname, :starttime, :endtime, :description, :eventhost, :address, :userid)",
                    eventname=request.get.form("eventName"), starttime=request.get.form("starttime"), endtime=request.get.form("endtime"),
                    description=request.get.form("description"), eventhost=request.get.form("host"), address=request.form.get("address"),
                    userid=session["user_id"])
        return redirect("/")
        return redirect("/")

    else:
        return render_template("form.html")



@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    # Get username through HTTP parameter
    username = request.args.get("username")

    # Query database for all usernames in users
    usernames = db.execute("SELECT username FROM users")

    # Check all dicts in list "usernames" for the input username, return true if username is unique and false if it is not, in JSON format
    if not any(d["username"] == username for d in usernames):
        return jsonify(True)
    else:
        return jsonify(False)

"""
@app.route("/friends")
@login_required
def friends():

"""


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        flash('Login successful!')

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash('Logged out!')

    # Redirect user to login form
    return redirect("/")

"""
@app.route("/addfriend", methods=["GET", "POST"])
@login_required
def addfriend():
    # TODO
"""

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Ensure password confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # Ensure password and confirmation match
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # Get username from input
        username = request.form.get("username")

        # Query database for users with the inputted username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        # If there are other users already with the inputted username, return an error
        if len(rows) != 0:
            return apology("username already taken", 400)

        # Insert user into table
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=username, hash=generate_password_hash(request.form.get("password")))

        # Remember user id for current session
        session["user_id"] = db.execute("SELECT id FROM users WHERE username = :username", username=username)[0]["id"]

        flash('Registered!')

        # Redirect to index
        return redirect("/")

    else:
        # Render register.html
        return render_template("register.html")

"""
@app.route("/deletefriend", methods=["GET", "POST"])
@login_required
def deletefriend():
    # TODO
"""


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change password."""

    if request.method == "POST":

        # Ensure old password was submitted
        if not request.form.get("oldpass"):
            return apology("must provide old password", 403)

        # Ensure new password was submitted
        elif not request.form.get("newpass"):
            return apology("must provide new password", 403)

        # Query database for username
        rows = db.execute("SELECT hash FROM users WHERE id = :userid", userid=session["user_id"])

        # Ensure password is correct
        if not check_password_hash(rows[0]["hash"], request.form.get("oldpass")):
            return apology("wrong old password", 403)

        # Update password for user
        db.execute("UPDATE users SET hash=:hash WHERE id = :userid",
                   userid=session["user_id"], hash=generate_password_hash(request.form.get("newpass")))

        flash('Password changed!')

        # Redirect to index
        return redirect("/")

    else:
        # Render password.html
        return render_template("password.html")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

@app.route("/table", methods=["GET"])
@login_required
def table():
    return render_template("table.html")


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

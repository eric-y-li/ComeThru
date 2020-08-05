import os
import json
import time

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
    """Display map"""

    # Delete events older than 1 day
    db.execute("DELETE from events WHERE julianday(CURRENT_TIMESTMAP)-julianday(timecreated) > 1")

    # Query database for id of friends of current user
    friendids = db.execute("SELECT friendid from friends WHERE userid = :userid", userid = session["user_id"])
    # Query database for all events, create new list for events to be displayed
    events = db.execute("SELECT * from events")
    displayevents = []
    
    # If event is private, add it if event creator's userid is one of user's friends; if public, add it regardless
    for i in events:
        if i["privacy"] == "T":
            for j in friendids:
                if i["userid"] == j["friendid"] or i["userid"] == session["user_id"]:
                    displayevents.append(i)

        else:
            displayevents.append(i)

    return render_template("index.html", displayevents = displayevents)


@app.route("/form", methods=["GET", "POST"])
@login_required
def form():
    """Get information for event"""
    
    if request.method == "POST":
        # Make sure they've clicked a host tag
        if not request.form.get("host"):
            return apology("Must select a host", 400)
        # Make sure they've entered an event name
        elif not request.form.get("eventName"):
            return apology("Must enter event name", 400)
        # Make sure they've entered description
        elif not request.form.get("description"):
            return apology("Must enter a description", 400)
        # Check for start time
        elif not request.form.get("starttime"):
            return apology("Must enter a start time", 400)
        # Check for endtime
        elif not request.form.get("endtime"):
            return apology("Must enter an end time", 400)

        # Create a pseudo-Boolean for privacy
        isprivate = "F"
        privacy = request.form.get("privacy")
        # Change the setting if the event is selected to be private
        if privacy == "private":
            isprivate = "T"
        
        # Convert times from military time to 12-hour time format
        starttime = time.strptime(request.form.get("starttime"), "%H:%M")
        starttime_12hour = time.strftime( "%I:%M %p", starttime )

        endtime = time.strptime(request.form.get("endtime"), "%H:%M")
        endtime_12hour = time.strftime( "%I:%M %p", endtime )
        
        # Get current user's username
        username = db.execute("SELECT username from users WHERE id = :userid", userid = session["user_id"])

        # Insert all the input into the events database including the user ID and username of the poster
        result = db.execute("INSERT INTO events (eventname, starttime, endtime, description, eventhost, userid, privacy, timecreated, createdby) VALUES (:eventname, :starttime, :endtime, :description, :eventhost, :userid, :privacy, CURRENT_TIMESTAMP), :username)",
                            eventname=request.form.get("eventName"), starttime=starttime_12hour, endtime=endtime_12hour,
                            description=request.form.get("description"), eventhost=request.form.get("host"),
                            userid=session["user_id"], privacy = isprivate, username = username[0]["username"])
        
        # Record the id of the created event in session, to be used in /location
        session["event_id"] = result

        return render_template("location.html")

    else:
        return render_template("form.html")

@app.route("/location", methods=["POST"])
def location():
    """Get event location"""
    if request.method == "POST":
        # Store data from ajax request as a dict
        data = request.get_json()
        # Update event (just created through /form) with coordinates of location and address
        db.execute("UPDATE events SET address = :address, latitude=:lat, longitude=:lng WHERE id=:eventid",
                    address=data["address"], lat=float(data["latitude"]), lng=float(data["longitude"]), eventid=session["event_id"])
    flaPosted!")
        return jsonify(dict(redirect='/'))

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


@app.route("/addfriend", methods=["GET", "POST"])
@login_required
def addfriend():
    # If its a GET render the appropriate html
    if request.method == "GET":
        return render_template("addfriends.html")
    else:
        # Select the requested user
        rows = db.execute("SELECT * FROM users WHERE username=:username", username=request.form.get("friendadd"))
        # Get their ID
        recipient_id = db.execute("SELECT id FROM users WHERE username=:username", username=request.form.get("friendadd"))
        # Check whether the current user has already sent the inputted username a request
        prequests = db.execute("SELECT * FROM requests WHERE sender=:sender AND recipient=:recipient", sender=session["user_id"], recipient=request.form.get("friendadd"))
        # Check whether the user with the requested username has already sent the session user a request
        prequests69 = db.execute("SELECT * FROM requests WHERE sender=:sender AND recipient=:recipient", sender=recipient_id[0]["id"], recipient=session["user_id"])
        # Check whether the two users are already friends
        prefriends = db.execute("SELECT * FROM friends WHERE friendid=:recipient AND userid=:sender", recipient=recipient_id[0]["id"], sender=session["user_id"])
        # If they do not enter any username
        if not request.form.get("friendadd"):
            return apology("must enter a friend to add", 400)
        # If the username they enter does not exist in the database
        elif len(rows) == 0:
            return apology("user does not exist", 403)
        # If there has been a request from session user to desired username already
        elif len(prequests) != 0:
            return apology("you have already requested this user", 403)
        # If there has been a reverse of the above
        elif len(prequests69) != 0:
            return render_template("request.html")
        # If the two are already friends
        elif len(prefriends) != 0:
            return apology("you and this user are already friends", 403)
        # Fetch the recipient's ID from the users db
        recipient = db.execute("SELECT id FROM users WHERE username=:username", username=request.form.get("friendadd"))
        sender_username = db.execute("SELECT username FROM users WHERE id=:id", id=session["user_id"])
        db.execute("INSERT INTO requests (sender, sender_username, recipient, recipient_username) VALUES (:sender, :sender_username, :recipient, :recipient_username)", sender=session["user_id"], sender_username=sender_username[0]["username"],recipient=recipient[0]["id"], recipient_username=request.form.get("friendadd"))


        flash("Requested!")

        return redirect("/")


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

@app.route("/table", methods=["GET"])
@login_required
def table():
    db.execute("DELETE from events WHERE julianday(datetime(CURRENT_TIMESTAMP,'localtime'))-julianday(timecreated) > 1")
    #friendids is a dict of friend ids that we then compare with the creators of events
    friendids = db.execute("SELECT friendid from friends where userid = :userid", userid = session["user_id"])
    #events stores all the information about events submitted through the form
    events = db.execute("SELECT * from events")
    rows = []
    #iterate through all events
    for i in events:
        #check the privacy setting
        if i["privacy"] == "T":
            #if private, iterate through friendids and compare the friend id to the creator of the event's id
            for j in friendids:
                #also check if it is an event created by the user
                if i["userid"] == j["friendid"] or i["userid"] == session["user_id"]:
                    rows.append(i)
        #all public events
        else:
            rows.append(i)
    return render_template("table.html", rows = rows)
@app.route("/about", methods=["GET"])
@login_required
def about():
    return render_template("about.html")

@app.route("/friends", methods=["GET", "POST"])
@login_required
def friends():
    # Select the usernames of the friends of the users
    rows = db.execute("SELECT friendname FROM friends WHERE userid=:userid", userid=session["user_id"])
    if request.method == "GET":
        return render_template("friends.html", rows = rows)
    else:
        # If the method is post it is because the user is trying to delete a friend
        if request.form.get("delete"):
          deletefriend = request.form.get("delete")
          # Because delete is 6 letters, [6:] indicates the portion of the string that is the name of the friend
          friendname = deletefriend[6:]
          # Friend relationships are stored both ways in the database so need to delete both relationships
          db.execute("DELETE FROM friends WHERE friendname=:friendname", friendname=friendname)
          db.execute("DELETE FROM friends WHERE username=:friendname", friendname=friendname)
          return redirect("/")



@app.route("/requests", methods=["GET", "POST"])
@login_required
def requests():
    # Rows is array of names of users that sent friend requests to the user in session
    rows = db.execute("SELECT sender_username FROM requests WHERE recipient=:recipient", recipient=session["user_id"])
    # Display requests page if its get
    if request.method == "GET":
        return render_template("request.html", rows = rows)
    # If the user clicks accept or decline
    else:
        # If request.form.get("choice"):
        choice = request.form.get("choice")
            # If the choice is an acceptance
        if choice[0] == "A":
                # Friendname is the name of the friend as choice[6:] is the part of the string that is the username
                friendname = choice[6:]
                # Access the id of the session user as well as the requestor
                friendid = db.execute("SELECT id FROM users WHERE username=:friendname", friendname=friendname)[0]["id"]
                username = db.execute("SELECT username FROM users WHERE id=:user_id", user_id=session["user_id"])[0]["username"]
                # Insert it into the database twice so that the friends display for each friend
                db.execute("INSERT INTO friends (userid, username, friendname, friendid) VALUES (:userid, :username, :friendname, :friendid)",
                            userid=session["user_id"], username=username, friendname=friendname, friendid=friendid)
                db.execute("INSERT INTO friends (userid, username, friendname, friendid) VALUES (:userid, :username, :friendname, :friendid)",
                            userid=friendid, username=friendname, friendname=username, friendid=session["user_id"])
                # Delete the request from the requests database and therefore also from the requests html
                db.execute("DELETE FROM requests WHERE sender_username=:friendname", friendname=friendname)
                return redirect("/friends")
        # If the option is to decline
        else:
            # Same thing as in the if statement but this time it's 7 as the 'Decline' has one more letter
            friendname = choice[7:]
            # Same thing as if statement
            # friendid = db.execute("SELECT id FROM users WHERE username=:friendname", friendname=friendname)[0]["id"]
            # username = db.execute("SELECT username FROM users WHERE id=:user_id", user_id=session["user_id"])[0]["username"]
            # Delete the request from the requests database
            db.execute("DELETE FROM requests WHERE sender_username=:friendname", friendname=friendname)
            return redirect("/")

@app.route("/check2", methods=["GET"])
def check2():
    """Return true if username available, else false, in JSON format"""
    # Get username through HTTP parameter
    username = request.args.get("username")

    myusername = db.execute("SELECT username FROM users WHERE id=:userid", userid=session["user_id"])[0]["username"]

    # Query database for friends of user
    usernames = db.execute("SELECT username FROM friends WHERE friendname = :username AND userid = :userid", username=username, userid=session["user_id"])
    # Take all usernames who you you have outstanding requests to
    usersfriendrequest = db.execute("SELECT recipient_username FROM requests WHERE sender_username=:username AND recipient_username=:myusername", username=username, myusername=myusername)
    # Combine the usernames from your outstanding requests with those that you have yet to respond to
    allrequests = usersfriendrequest + db.execute("SELECT sender_username FROM requests WHERE recipient_username=:username AND sender_username=:myusername", username=username, myusername=myusername)

    print(allrequests)

    # Query database for all usernames in users
    allusernames = db.execute("SELECT username FROM users")

    if not any(d["username"] == username for d in allusernames):
        return jsonify("nouserexists")
    elif len(usernames) != 0:
        return jsonify("friendexists")
    elif len(allrequests) != 0:
        return jsonify("requestexists")
    else:
        return jsonify("noerror")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

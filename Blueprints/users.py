from flask import render_template, request, redirect, url_for, session, flash, Blueprint
from datetime import datetime, timedelta, timezone
from functools import wraps
import re
import pyotp
from Modules import AES256, Auth, SHA256, Functions
from db import mongo
from pymongo import ASCENDING
import requests

UserBP = Blueprint('users', __name__)

def LoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            session_key = session['key']
            # username = session['username']
            userid = session['userid']
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            user_session = mongo.db.UserSessions.find_one({
                'SessionKey': session_key,
                # 'UserName': username,
                'UserID': userid,
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'ExpirationTime': {'$gt': datetime.now(timezone.utc)}
            })
            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('users.Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('users.Login'))
    return decorated_function

def NotLoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            return redirect(url_for('users.Index'))
        return view_func(*args, **kwargs)
    return decorated_function

def is_safe_url(target):
    # Implement a function to check if a given URL is safe for redirection
    # This function helps prevent Open Redirect vulnerabilities

    # host_url = request.host_url
    # test_url = urljoin(host_url, target)
    # return urlparse(host_url).netloc == urlparse(test_url).netloc
    return target

def OnboardingCheck(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            user = mongo.db.Users.find_one({'UserName': session['username']})
            if "Phone" not in user or "Gender" not in user or "DOB" not in user or "Country" not in user: 
                return redirect(url_for('users.Onboarding'))
        return view_func(*args, **kwargs)
    return decorated_function

@UserBP.route('/dashboard')
@LoggedInUser
@OnboardingCheck
def Index():
    return f'Logged in as {session["username"]}! <a href="{url_for("users.Logout")}">Logout</a><br> <a href="{url_for("users.Profile")}">Profile</a>'

@UserBP.route('/register', methods=['GET', 'POST'])
@NotLoggedInUser
def Registration():
    if request.method == 'POST':
        datecreated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name =  request.form['name']
        username = request.form['username']
        email =  request.form['email']
        password = request.form['password']
        userid = AES256.GenerateRandomString()

        while mongo.db.Users.find_one({'UserID': userid}):
            userid = AES256.GenerateRandomString()
    
        UserNameCheck = False if re.match(r'^[a-zA-Z0-9_]{4,}$', username) else True
        # PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', password) else True
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$', password) else True
        ExistingUserName = True if mongo.db.Users.find_one({'UserName': username}) else False
        ExistingEmailID = True if mongo.db.Users.find_one({'Email': email}) else False

        if UserNameCheck or PasswordCheck or ExistingUserName or ExistingEmailID:
            ErrorMessages = []
            if UserNameCheck:
                ErrorMessages.append('Invalid username. It should be at least 4 characters and contain only alphabets (lower and upper), numbers, and underscores.')
            if PasswordCheck:
                ErrorMessages.append('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.')
            if ExistingUserName:
                ErrorMessages.append('Username already exists. Please choose a different username.')
            if ExistingEmailID:
                ErrorMessages.append('Email ID already Registered. Try Logging in.')
            flash(ErrorMessages, 'error')
            return redirect(url_for('users.Registration'))

        nameE = AES256.Encrypt(name, AES256.DeriveKey(userid, datecreated, "Name"))
        passwordH = SHA256.HashPassword(password, userid)

        Auth.SendVerificationEmail(username, email, Auth.GenerateVerificationCode())

        mongo.db.Users.insert_one({
            'UserID': userid, 
            'UserName': username, 
            'Name': nameE, 
            'Email': email, 
            'Password': passwordH, 
            'DateCreated': datecreated,
            'Locked': False
        })

        mongo.db.UserPermissions.insert_one({'UserID': userid, "SitePermissions": None})

        return redirect(url_for('users.VerifyAccount', username=username))
    return render_template('Users/Register.html')

@UserBP.route('/verifyaccount/<username>', methods=['GET', 'POST'])
@NotLoggedInUser
def VerifyAccount(username):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = mongo.db.UserVerification.find_one({'UserName': username, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('users.Login', username=username))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            mongo.db.UserVerification.update_one({'UserName': username}, {'$set': {'Verified': True}})
            return redirect(url_for('users.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('users.VerifyAccount', username=username))

    return render_template('Users/VerifyAccount.html', username=username)

# def LockAccount(UserID, Lock):
#     mongo.db.Users.update_one({'UserID': UserID}, {'$set': {'Locked': Lock}})
#     return True

@UserBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInUser
def Login():
    next_url = request.args.get('next')
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        platform = request.form.get('platform')
        language = request.form.get('language')
        screen_resolution = request.form.get('screenresolution')
        timezone_offset = int(request.form.get('timezoneoffset'))/60
        date = request.form.get('date')
        time = request.form.get('time')
        useragent = request.headers.get('User-Agent')
        ipaddress = request.remote_addr

        # if js collected invisible input blank then consider it as bot

        # Remove in Prod
        ipcheck = ipaddress
        if ipcheck=="127.0.0.1":
            ipcheck="152.58.213.171"

        response = requests.get('https://api.findip.net/' + ipcheck + '/?token=9760606036624d2d99873fd9bd59aea9')
        ipdetails = response.json() if response.status_code == 200 else {}

        currenttime = datetime.now(timezone.utc)

        SessionData = {
            "IPAddress": ipaddress,
            "UserAgent": useragent,
            "Platform": platform,
            "Language": language,
            "ScreenResolution": screen_resolution,
            "TimeZone": timezone_offset,
            "DeviceDate": date,
            "DeviceTime": time,
            "City": ipdetails.get('city', {}).get('names', {}).get('en'),
            "Country": ipdetails.get('country', {}).get('names', {}).get('en'),
            "Latitude": ipdetails.get('location', {}).get('latitude'),
            "Longitude": ipdetails.get('location', {}).get('longitude'),
            "TimeZone": ipdetails.get('location', {}).get('time_zone'),
            "ISP": ipdetails.get('traits', {}).get('isp'),
            'CreatedAt': currenttime,
            'ExpirationTime': currenttime + timedelta(hours=6)
        }   

        if "@" in login:
            user = mongo.db.Users.find_one({'Email': login})
        else:
            user = mongo.db.Users.find_one({'UserName': login})

        if user["Locked"]:      
            Functions.SendUnlockKey(user)
            flash('Account Locked! Check your E-Mail to Reactivate the Account', 'error')
            return redirect(url_for('users.Login'))

        if user:
            UserLoginAttempts = list(mongo.db.UserLoginAttempts.find({'UserID': user["UserID"]}))

            StatusCounts = {'Success': 0, 'Failed': 0}
            ReasonCounts = {
                'Password Correct, 2FA Correct': 0,
                'Password Incorrect': 0,
                'Password Correct': 0,
                'Password Correct, 2FA Incorrect': 0
            }

            for Attempt in UserLoginAttempts:
                Status = Attempt['Status']
                Reason = Attempt['Reason']
                
                if Status in StatusCounts:
                    StatusCounts[Status] += 1
                
                if Reason in ReasonCounts:
                    ReasonCounts[Reason] += 1

            if ReasonCounts["Password Incorrect"] >= 5:
                Functions.LockAccount(user["UserID"], True)
                Functions.SendUnlockKey(user)
                flash('Account Locked! Multiple Incorrect Login Attempts Detected. Check your E-Mail to Reactivate the Account.', 'error')
                return redirect(url_for('users.Login'))
                
            elif ReasonCounts["Password Correct, 2FA Incorrect"] >= 5:
                Functions.LockAccount(user["UserID"], True)
                Functions.SendUnlockKey(user)            
                flash('Account Locked! Multiple Incorrect Login Attempts Detected. Check your E-Mail to Reactivate the Account.', 'error')
                return redirect(url_for('users.Login'))
              
            elif (StatusCounts["Success"] + StatusCounts["Failed"]) >= 15:
                Functions.LockAccount(user["UserID"], True)
                Functions.SendUnlockKey(user)
                flash('Account Locked! Multiple Login Attempts Detected. Check your E-Mail to Reactivate the Account.', 'error')
                return redirect(url_for('users.Login'))

        else:
            flash('Invalid Login or Password', 'error')
            return redirect(url_for('users.Login'))
        
        if not Auth.IsUserVerified(user["UserName"]):
            flash('User not verified! Please complete the OTP verification', 'error')
            return redirect(url_for('users.VerifyAccount', username=user["UserName"]))

        if SHA256.CheckPassword(password, user["Password"], user["UserID"]):
            if Auth.Is2FAEnabled(user["UserName"]):
                session['2fa_user'] = user["UserName"]
                
                next_url = request.args.get('next')

                session['SessionData'] = SessionData

                if next_url:
                    if is_safe_url(next_url):
                        session['next_url'] = next_url
                        return redirect(url_for('users.Verify2FA'))
                else:
                    return redirect(url_for('users.Verify2FA'))
            
            sessionkey = Auth.GenerateSessionKey()  

            mongo.db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                # 'UserName': user["UserName"],
                'UserID': user["UserID"],
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            }) 
            mongo.db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            UserLoginAttemptData = {
                # 'UserName': user["UserName"],
                'UserID': user["UserID"],
                'Status': 'Success',
                'Reason': 'Password Correct'
            }

            UserLoginAttemptData.update(SessionData)
            mongo.db.UserLoginAttempts.insert_one(UserLoginAttemptData) 
            mongo.db.UserLoginAttempts.create_index('ExpirationTime', expireAfterSeconds=0)

            session['key'] = sessionkey
            session['username'] = user["UserName"]
            session['userid'] = user["UserID"]

            next_url = request.args.get('next')  
            print(next_url)
            if next_url:
                if is_safe_url(next_url):
                    return redirect(next_url)
            return redirect(url_for('users.Index'))
        else:
            UserLoginAttemptData = {
                # 'UserName': user["UserName"],
                'UserID': user["UserID"],
                'Status': 'Failed',
                'Reason': 'Password Incorrect'
            }

            UserLoginAttemptData.update(SessionData)
            mongo.db.UserLoginAttempts.insert_one(UserLoginAttemptData)
            mongo.db.UserLoginAttempts.create_index('ExpirationTime', expireAfterSeconds=0)

            flash('Invalid Login or password', 'error')
    
    return render_template('Users/Login.html')

@UserBP.route('/unlock/<UnlockKey>', methods=['GET'])
@NotLoggedInUser
def Unlock(UnlockKey):
    Key = mongo.db.UserUnlockAccount.find_one({'UnlockKey': UnlockKey})

    if Key:
        UserLoginAttempts = list(mongo.db.UserLoginAttempts.find({'UserID': Key["UserID"]}))

        if UserLoginAttempts:
            mongo.db.UserLoginAttempts.delete_many({'UserID': Key["UserID"]})

            for Attempts in UserLoginAttempts:
                for key in ['_id', 'ScreenResolution', 'DeviceDate', 'DeviceTime', 'Latitude', 'Longitude', 'Language', 'ExpirationTime', 'UserAgent', 'ISP']:
                    if key in Attempts:
                        del Attempts[key]
                Attempts['ExpirationTime'] = Attempts['CreatedAt'] + timedelta(hours=6) # Change on Prod: timedelta(days=7)

            mongo.db.UserLoginAttemptsHistory.insert_many(UserLoginAttempts)
            mongo.db.UserLoginAttemptsHistory.create_index([('ExpirationTime', ASCENDING)], expireAfterSeconds=0)

        Functions.LockAccount(Key["UserID"], False)
        mongo.db.UserUnlockAccount.delete_one({'UserID': Key["UserID"]})
    
        flash('Account Unlocked Successfully! Login Now.', 'error')
        return redirect(url_for('users.Login'))

    else:
        flash('Incorrect Unlock Key! Try Again.', 'error')
        return redirect(url_for('users.Login'))
    
@UserBP.route('/verify2fa', methods=['GET', 'POST'])
@NotLoggedInUser
def Verify2FA():
    if '2fa_user' not in session or 'SessionData' not in session:
        return redirect(url_for('users.Login'))

    username = session['2fa_user']
    user = mongo.db.Users.find_one({'UserName': username})
    next_url = session.get('next_url')

    if user["Locked"]:    
        Functions.SendUnlockKey(user)
        flash('Account Locked! Check your E-Mail to Reactivate the Account', 'error')
        return redirect(url_for('users.Login'))
        
    if user:
        UserLoginAttempts = list(mongo.db.UserLoginAttempts.find({'UserID': user["UserID"]}))

        ReasonCounts = {
            'Password Correct, 2FA Correct': 0,
            'Password Incorrect': 0,
            'Password Correct': 0,
            'Password Correct, 2FA Incorrect': 0
        }

        for Attempt in UserLoginAttempts:
            Reason = Attempt['Reason']
            
            if Reason in ReasonCounts:
                ReasonCounts[Reason] += 1

        if ReasonCounts["Password Correct, 2FA Incorrect"] >= 5:
            Functions.LockAccount(user["UserID"], True)
            Functions.SendUnlockKey(user)

            flash('Account Locked! Multiple Incorrect Login Attempts Detected. Check your E-Mail to Reactivate the Account.', 'error')
            return redirect(url_for('users.Login'))
    
    else:
        flash('Invalid Login or Password', 'error')
        return redirect(url_for('users.Login'))      

    if request.method == 'POST':
        entered_otp = request.form['otp']
        totp_secret = user.get('TwoFactorSecret', '')
        SessionData = session.get('SessionData')
        
        next_url = session.get('next_url')
        if next_url:
            session.pop('next_url')

        if not totp_secret:
            flash('2FA not enabled for this user.', 'error')
            return redirect(url_for('users.Login'))

        totp = pyotp.TOTP(totp_secret)

        if totp.verify(entered_otp):
            sessionkey = Auth.GenerateSessionKey()
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr

            currenttime = datetime.now(timezone.utc)
            mongo.db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                # 'UserName': user["UserName"],
                'UserID': user["UserID"],
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            })
            mongo.db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            UserLoginAttemptData = {
                # 'UserName': user["UserName"],
                'UserID': user["UserID"],
                'Status': 'Success',
                'Reason': 'Password Correct, 2FA Correct'
            }
            UserLoginAttemptData.update(SessionData)
            mongo.db.UserLoginAttempts.insert_one(UserLoginAttemptData) 
            mongo.db.UserLoginAttempts.create_index('ExpirationTime', expireAfterSeconds=0)

            session['key'] = sessionkey
            session['username'] = user["UserName"]
            session['userid'] = user["UserID"]

            session.pop('2fa_user')
            session.pop('SessionData')

            if next_url:
                if is_safe_url(next_url):
                    return redirect(next_url)
            else:
                return redirect(url_for('users.Index'))
        else:
            UserLoginAttemptData = {
                # 'UserName': user["UserName"],
                'UserID': user["UserID"],
                'Status': 'Failed',
                'Reason': 'Password Correct, 2FA Incorrect'
            }
            UserLoginAttemptData.update(SessionData)
            mongo.db.UserLoginAttempts.insert_one(UserLoginAttemptData) 
            mongo.db.UserLoginAttempts.create_index('ExpirationTime', expireAfterSeconds=0)
        
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('Users/Verify2FA.html', username=username, next=next_url)

@UserBP.route('/forgotpassword', methods=['GET', 'POST'])
@NotLoggedInUser
def ForgotPassword():
    if request.method == 'POST':
        login = request.form['login']

        if "@" in login:
            user = mongo.db.Users.find_one({'Email': login})
        else:
            user = mongo.db.Users.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Email ID', 'error')
            return redirect(url_for('users.ForgotPassword'))

        ResetKey = AES256.GenerateRandomString(32)
        Auth.PasswordResetMail(user["UserName"], user["Email"], ResetKey)
        flash('A Password Reset Link has been sent to your Email! Please check your Inbox and Follow the Instructions', 'info')
    return render_template('Users/ForgotPassword.html')

@UserBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
@NotLoggedInUser
def ResetPassword(ResetKey):
    if request.method == 'POST':
        NewPassword = request.form['password']
            
        ResetData = mongo.db.PasswordReset.find_one({'ResetKey': ResetKey})

        if not ResetData:
            flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('users.ResetPassword', ResetKey=ResetKey))
        
        user = mongo.db.Users.find_one({'UserName': ResetData['UserName']})

        passwordH = SHA256.HashPassword(NewPassword, user["UserID"])

        mongo.db.Users.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordH}})

        mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
        flash('Password reset successful. Try Loggin in.', 'info')

        # return redirect(url_for('users.Login'))
    return render_template('Users/ResetPassword.html', ResetKey=ResetKey)

@UserBP.route('/logout')
@LoggedInUser
def Logout():
    session_key = session['key']
    # username = session['username']
    userid = session['userid']
    mongo.db.UserSessions.delete_one({
        'SessionKey': session_key,
        'UserID': userid
    })
    session.clear()
    return redirect(url_for('users.Index'))

# 2FA

@UserBP.route('/2fa', methods=['GET', 'POST'])
@LoggedInUser
def Toggle2FA():
    username = session['username']
    user = mongo.db.Users.find_one({'UserName': username})

    QRImage = ""
    if user.get('TwoFactorEnabled', False):
        QRImage = Auth.Generate2FAQR(user["UserName"], user["TwoFactorSecret"])

    if request.method == 'POST':
        if user and user.get('TwoFactorEnabled', False):
            mongo.db.Users.update_one({'UserName': username}, {'$unset': {'TwoFactorEnabled': '', 'TwoFactorSecret': ''}})
            flash('Two-factor authentication has been disabled for your account.', 'success')
        else:
            user_secret = Auth.Generate2FASecret()
            mongo.db.Users.update_one({'UserName': username}, {'$set': {'TwoFactorEnabled': True, 'TwoFactorSecret': user_secret}})
            flash('Two-factor authentication has been enabled for your account.', 'success')
            
        return redirect(url_for('users.Toggle2FA'))
    return render_template('Users/2FA.html', user=user, QRImage=QRImage)

@UserBP.route('/onboarding', methods=['GET','POST'])
@LoggedInUser
def Onboarding():
    if request.method == 'POST':
        username = session['username']
        user = mongo.db.Users.find_one({'UserName': username})
    
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        gender = request.form['gender']
        dob = request.form['dob']
        country = request.form['country']
    
        EncryptedData = {}
        
        if name:
            EncryptedData["Name"] = AES256.Encrypt(name, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name"))
        if email:
            EncryptedData["Email"] = email
        if phone:    
            EncryptedData["Phone"] = AES256.Encrypt(phone, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Phone"))
        if gender:
            EncryptedData["Gender"] = AES256.Encrypt(gender, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Gender"))
        if dob:
            EncryptedData["DOB"] = AES256.Encrypt(dob, AES256.DeriveKey(user["UserID"], user["DateCreated"], "DOB"))
        if country:
            EncryptedData["Country"] = AES256.Encrypt(country, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Country"))

        mongo.db.Users.update_one({'UserName': username}, {'$set': EncryptedData})

        return redirect(url_for('users.Index'))
        
    username = session['username']
    user = mongo.db.Users.find_one({'UserName': username})

    if "Phone" in user and "Gender" in user and "DOB" in user and "Country" in user: 
        return redirect(url_for('users.Index'))
    
    DecryptedData = {}

    if "Name" in user: 
        DecryptedData["Name"] = AES256.Decrypt(user["Name"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name"))
    if "Email" in user: 
        DecryptedData["Email"] = user["Email"]
    if "Phone" in user: 
        DecryptedData["Phone"] = AES256.Decrypt(user["Phone"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Phone"))
    if "Gender" in user: 
        DecryptedData["Gender"] = AES256.Decrypt(user["Gender"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Gender"))
    if "DOB" in user: 
        DecryptedData["DOB"] = AES256.Decrypt(user["DOB"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "DOB"))
    if "Country" in user: 
        DecryptedData["Country"] = AES256.Decrypt(user["Country"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Country"))

    return render_template('Users/UserOnboarding.html', DecryptedData=DecryptedData)

@UserBP.route('/profile', methods=['GET'])
@LoggedInUser
def Profile():
    username = session['username']
    user = mongo.db.Users.find_one({'UserName': username})

    keys = Functions.GetDocumentKeys(username, mongo)

    if user:
        DecryptedData = {
            'UserName': user["UserName"],
            'Name': AES256.Decrypt(user["Name"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name")),
            'Email': user["Email"],
            'Gender': AES256.Decrypt(user["Gender"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Gender")),
            'Phone': AES256.Decrypt(user["Phone"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Phone")),
            'Country': AES256.Decrypt(user["Country"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Country")),
            'DOB': AES256.Decrypt(user["DOB"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "DOB")),
        }
        return render_template('Users/Profile.html', DecryptedData=DecryptedData)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('users.Login'))

@UserBP.route('/profile/edit', methods=['GET', 'POST'])
@LoggedInUser
def EditProfile():
    if request.method == 'POST':
        username = session['username']
        user = mongo.db.Users.find_one({'UserName': username})

        NewName = request.form['name']

        NewNameE = AES256.Encrypt(NewName, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name"))

        mongo.db.Users.update_one({'UserName': username}, {'$set': {'Name': NewNameE}})
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('users.Profile'))

    username = session['username']
    user = mongo.db.Users.find_one({'UserName': username})

    DecryptedData = {
        'Name': AES256.Decrypt(user["Name"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name")),
        'UserName': user["UserName"],
        'Email': user["Email"]
    }

    return render_template('Users/EditProfile.html', DecryptedData=DecryptedData)

def Del():
    None

@UserBP.route('/dashboard1')
@LoggedInUser
def Dashboard():
    UserName = session['username']
    User = mongo.db.Users.find_one({'UserName': UserName})
    UserID = User["UserID"]
    UserPermissionsData = mongo.db.UserPermissions.find_one({'UserID': UserID})

    print(UserPermissionsData)
    UserPermissions = []

    # if UserPermissionsData and 'SitePermissions' in UserPermissionsData:
    if UserPermissionsData and 'SitePermissions' in UserPermissionsData and UserPermissionsData['SitePermissions'] is not None:
        SiteIDs = list(UserPermissionsData['SitePermissions'].keys())

        for SiteID in SiteIDs:
            permissions = UserPermissionsData['SitePermissions'].get(SiteID, [])
            if not isinstance(permissions, list):
                permissions = []

            permissions_str = ', '.join(permissions)
            result = mongo.db.Sites.find_one({'SiteID': SiteID})

            SiteName = result.get('SiteName') if result and 'SiteName' in result else None

            if not SiteName:
                mongo.db.UserPermissions.update_one({"UserID": UserID}, {"$unset": {f"SitePermissions.{SiteID}": ""}})
                continue

            UserPermissions.append({
                'SiteID': SiteID,
                'SiteName': SiteName,
                'Permissions': permissions_str
            })
    else:
        SiteIDs = []       
    return render_template("Users/Dashboard.html", UserPermissions=UserPermissions)

@UserBP.route('/edit/<SiteID>', methods=['GET', 'POST'])
@LoggedInUser
def EditPermissions(SiteID):
    UserName = session['username']

    if request.method == 'POST':
        SelectedPermissions = request.form.getlist('permissions[]')

        User = mongo.db.Users.find_one({'UserName': UserName})
        UserID = User["UserID"]

        mongo.db.UserPermissions.update_one(
            {'UserID': UserID},
            {'$set': {'SitePermissions.' + SiteID: SelectedPermissions}}
        )

        return redirect(url_for('users.Dashboard'))

    User = mongo.db.Users.find_one({'UserName': UserName})
    UserID = User["UserID"]

    UserPermissionsData = mongo.db.UserPermissions.find_one({'UserID': UserID})
    SitePermissionsData = mongo.db.Sites.find_one({'SiteID': SiteID})
    UserData = mongo.db.Users.find_one({'UserID': UserID})

    Ignore = ['_id', 'DateCreated', 'Password', 'TwoFactorEnabled', 'TwoFactorSecret']

    UserDataAvailable = [element for element in list(UserData.keys()) if element not in Ignore]

    SiteName = SitePermissionsData["SiteName"]
    UserPermissions = UserPermissionsData["SitePermissions"][SiteID]
    SitePermissions = SitePermissionsData["SitePermissions"]
    NotAvailableData = [element for element in SitePermissions if element not in UserDataAvailable]
    
    return render_template("Users/EditPermissions.html", SiteName=SiteName, UserPermissions=UserPermissions, SitePermissions=SitePermissions, NotAvailableData=NotAvailableData)

@UserBP.route('/deletepermissions/<string:SiteID>', methods=['GET', 'POST'])
@LoggedInUser
def DeletePermissions(SiteID):
    UserName = session['username']
    User = mongo.db.Users.find_one({'UserName': UserName})
    UserID = User["UserID"]

    mongo.db.UserPermissions.update_one({"UserID": UserID}, {
        "$unset": {
            f"SitePermissions.{SiteID}": 1,
            f"Sites.{SiteID}": 1
        }
    })
    return redirect(url_for('users.Dashboard'))

@UserBP.route('/dash')
def Dash1():
    return render_template("Users/dash.html")

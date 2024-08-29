from flask import Flask, jsonify, request, Blueprint, render_template, redirect, url_for, session
from flask_sock import Sock
from uuid import uuid4
import random
import database_helper
from pydoc import stripid
from email_validator import validate_email, EmailNotValidError
import time
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
from flask import make_response
import copy
import hashlib
import hmac
import datetime

app = Flask(__name__)
app.secret_key = "s3cr3tk3y"
sock = Sock(app)
sock.init_app(app)
bcrypt = Bcrypt(app)
CORS(app)

hmac_secret = b"s3cr3tk3y"
##app_blueprint = Blueprint('app_blueprint', __name__)
#auth = Blueprint("auth", __name__)
app.config['HMAC_KEY'] = 's3cr3tk3y'  # define the secret key in an app config
########################################Google auth######################################
#@app.before_request
#def before_request():
#    try:
#        hmac.validate_signature(request)
#    except HmacException:
#        return abort(400)
    
oauth = OAuth(app)  
google = oauth.register(  # Google auth passwords and links 
    name='google',
    client_id="70797268274-j80sq023t4pd3t3nttnhtvoq0krvq1s5.apps.googleusercontent.com",  # one of two passwords 
    client_secret="placeholder_secret",
    #client_id="299420573322-l49ugqrt4ca9hh4miuv54vd8dnnq2qln.apps.googleusercontent.com",
    access_token_params=None,
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'}, # what data we get from google
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration'
    
)

@app.route('/login_google' , methods = ["GET"])
def login():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri) # authorize google server if login pass 

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    print(token)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()

    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    if not database_helper.check_valid_email(user_info["email"]): # checks if the account is new
        user = database_helper.insert_into_users(user_info["email"], None, user_info["given_name"], user_info["family_name"],"Undisclosed","Undisclosed", user_info["locale"]) # Creates a new account 
    database_helper.insert_google_into_tokens(user_info["email"], token['access_token']) # signs in the user 
    response = make_response(redirect(url_for('root')))
    response.set_cookie('access_token', token['access_token'], httponly=False) # sets a cookie with the token inside 
    return response

#########################################################################################
@app.errorhandler(404)  # all the path that we have not coverd gets re routed to /
def default(e):
    print(e)
    return root()

@app.route("/")
def root():
    return app.send_static_file("client.html") # gets website

@app.teardown_request
def after_request(exception):
    database_helper.disconnect_db()


ws_dic = {} # ative websocet dict that email -> ws 

@sock.route('/ws_connect')
def websocket_connect(ws): #first message from client 
    while True:
        token = ws.receive() # token from the user 
        if database_helper.check_valid_token(token): # loged in?  
            email = database_helper.get_email_from_token(token) 
            if email:
                if email in ws_dic: # has a active connection? Yes -> sign out the old user  
                    old_ws = ws_dic[email] # get old conection 
                    del ws_dic[email] # delete the old conection from the dict 
                    ws_dic[email] = ws # sets the new conection 
                    try:
                        old_ws.send("False") # sends sign out to old user 
                    except Exception as e:
                        print(e)
                        print("Tried closing an already closed websocket connection. Quitting.") 
                else:    
                    ws_dic[email] = ws # insert the new active conenction
        else: 
            ws.send("False") # not logged in 

def close_websocket(token): 
    if database_helper.check_valid_token(token):
            email = database_helper.get_email_from_token(token)
            if email and email in ws_dic:
                ws = ws_dic[email]
                try:
                    ws.send("False") # signs out current ws 
                except Exception as e:
                    print(e)
                    print("Tried closing an already closed websocket connection. Quitting.")
                del ws_dic[email]    

@app.route("/get_user_data_by_email/<email>", methods = ["GET"]) # methods = gives allowed methods 
def get_user_information_by_email(email):
    token = request.headers.get('Authorization') # Get the token from the header sent 

    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    if valid_hmac(token.encode(),hmac_resp,timestamp):
        if token is not None and database_helper.check_valid_token(token):
            if email is not None:
                if database_helper.check_valid_email(email):
                    user = database_helper.get_userdata(email) # get data from db
                    if user:
                        return jsonify({"success":True, "message":"Successfully found user information","data":user[0]}), 200 # Return status code 200 ok with data
                    else:
                        return jsonify({"success":False ,"message": "Something went wrong fetching user data"}), 500 # db faild 
                else:
                    return jsonify({"success":False ,"message": "email not found"}), 404 # wrong email 
            else:
                return jsonify({"success":False,"message": "Not good data"}), 400 # missing data 
        else:
            return jsonify({"success":False, "message": "Invalid token"}), 401 # not logged in
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403 
    
@app.route("/get_user_data_by_token", methods = ["GET"]) # methods = gives allowed methods 
def get_user_information_by_token():
    token = request.headers.get('Authorization')

    data= request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    if valid_hmac(token.encode(),hmac_resp,timestamp):
        if token is not None and database_helper.check_valid_token(token):
            email = database_helper.get_email_from_token(token) 
            return get_user_information_by_email(email) # uses the same function as with email but with the email conected with the token 
        else:
            return jsonify({"success":False, "message": "Invalid token"}), 401 # not logged in
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403 

@app.route("/get_user_messages_by_email/<email>", methods = ["GET"])
def get_user_messages_by_email(email):
    token = request.headers.get('Authorization') # get token 

    data= request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    if valid_hmac(token.encode(),hmac_resp,timestamp):
        if token is not None and database_helper.check_valid_token(token): # logged in? 
            if email is not None: # have a email data feald
                if database_helper.check_valid_email(email):# valid email?
                    posts = database_helper.get_user_messages_by_email(email)
                    if type(posts) != bool: # if fail then it is a bool, otherwise it is data
                        return jsonify({"success":True, "message":"Successfully got user messages" ,"data": posts}), 200
                    else:
                        return jsonify({"success":False ,"message": "Something went wrong fetching post"}), 500 # db crash
                else:
                    return jsonify({"success":False ,"message": "email not found"}), 404 # wrong email
            else:
                return jsonify({"success":False, "message": "Invalid Email"}), 400 # no email
        else:
            return jsonify({"success":False, "message": "Invalid token"}), 401 # not logged in
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403 
    
@app.route("/get_user_messages_by_token", methods = ["GET"])
def get_user_messages_by_token():
    token = request.headers.get('Authorization')

    data= request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    if valid_hmac(token.encode(),hmac_resp,timestamp):
        if token is not None and database_helper.check_valid_token(token):
            email = database_helper.get_email_from_token(token)
            return get_user_messages_by_email(email) # uses the same function as with email but with the email conected with the token 
        else:
            return jsonify({"success":False, "message": "Invalid token"}), 401 # not logged in 
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403

@app.route("/post_message", methods = ["POST"])
def make_post():
    try:
        json_dic = request.get_json()
        inputs = ["message"]
        token = request.headers.get('Authorization')

        data= request.data
        hmac_resp = request.headers.get("X-HMAC")
        timestamp = request.headers.get("X-TIMESTAMP")
        if valid_hmac(data,hmac_resp,timestamp):
            if token is None or not database_helper.check_valid_token(token):
                return jsonify({"success": False, "message":"Incorrect token"}), 401 # not logged in 
            elif not_missing_fields(json_dic, inputs): # if thre are text and not null in all fealds 
                emailfrom = database_helper.get_email_from_token(token) #get logged in email
                emailto = json_dic["email"]
                if not emailto: # chack if own profile post
                    emailto = emailfrom
                message = json_dic["message"]
                if len(message.strip())>0: # checks of message have any symbols apart from emty and space       
                    if (database_helper.check_valid_email(emailto)): # valid email
                        resp = database_helper.insert_into_posts(emailto, emailfrom, message)
                        if resp:
                            return jsonify({"success":True, "message": "Successfully created post"}), 201 # ok no data sent back
                        else:
                            return jsonify({"success":False,"message": "Something went wrong creating post"}), 500 # db crash
                    else:
                        return jsonify({"success":False,"message": "email not found"}), 404 # wrong email
                else: 
                    return jsonify({"success":False,"message": "empty message"}), 400 # empty message 
            else:
                return jsonify({"success":False,"message": "data missing"}), 400 # Missing fealds
        else:
            return jsonify({"success":False,"message": "Method not allowed"}), 403 
    except Exception as e:
        print(e)
        return jsonify({"success":False,"message": "Something went wrong creating post"}), 500 # db crash       


@app.route("/sign_up", methods = ["POST"]) # methods = gives allowed methods 
def sign_up():
 
    json_dic = request.get_json()
    descriptions = ["email", "password", "firstname", "familyname", "gender", "city", "country"]

    data= request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    if valid_hmac(data,hmac_resp,timestamp):
        if not_missing_fields(json_dic,descriptions): # if thre are text and not null in all fealds 
            if not len(json_dic["email"].strip())>0: # check email len
                return jsonify({"success":False,"message": "missing email"}), 400 # wrong email
            elif validate_emails(json_dic["email"]): # email validator 
                user_exists = database_helper.get_userdata(json_dic["email"])
                if user_exists:
                    return jsonify({"success":False,"message": "User already exists"}), 409
                else:
                    #inserting into db with a hashed and salted password and all other data 
                    resp = database_helper.insert_into_users(json_dic["email"], bcrypt.generate_password_hash(json_dic["password"]).decode("utf-8"), json_dic["firstname"], json_dic["familyname"], json_dic["gender"], json_dic["city"], json_dic["country"]) 
                    if resp: 
                        return jsonify({"success":True, "message": "Successfully created user"}), 201 # sing up success 
                    else:
                        return jsonify({"success":False,"message": "Creating user went wrong"}), 500 # db error
            else:
                return jsonify({"success":False,"message": "invalid email"}), 400 # invalid email
        else:
            return jsonify({"success":False,"message": "data missing"}), 400 # data is missing 
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403
    
@app.route("/sign_in", methods = ["POST"]) # methods = gives allowed methods 
def sign_in():
    json_dic = request.get_json()
    descriptions = ["username", "password"]

    data= request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    
    if valid_hmac(data,hmac_resp,timestamp): # Old and new hmac are the same and timestamp is not older than defined ttl
        if not_missing_fields(json_dic,descriptions):# if thre are text and not null in all fealds 
                passhash = database_helper.get_password_from_email(json_dic["username"]) # get the password hash from db 
                if passhash: # chcks if there were a email in the db 
                    if bcrypt.check_password_hash(passhash, json_dic["password"]): # chcks if the password hash were the same as the password from client 
                        token = database_helper.insert_into_tokens(json_dic["username"]) # get a token 
                        if token:
                            return jsonify({"success":True, "message": "Successfully signed in", "data": token}), 200 # ok return token to client 
                        else: 
                            return jsonify({"success":False,"message": "Something went wrong signing in."}), 500 # what code suits this better, it is not ok its error
                    else:
                        return jsonify({"success":False,"message": "Incorrect username or password"}), 401 # (wrong password)
                else:
                    return jsonify({"success":False,"message": "Incorrect username or password"}), 401 # (wrong username)
        else:
            return jsonify({"success":False,"message": "data missing"}), 400   
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403 
    
@app.route("/change_password", methods=["PUT"])
def change_password():
    json_dic = request.get_json()
    descriptions = ["oldpassword", "newpassword"]
    token = request.headers.get('Authorization')

    data= request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    
    if valid_hmac(data,hmac_resp,timestamp):
        if not_missing_fields(json_dic, descriptions):# if thre are text and not null in all fealds 
            oldPassword =json_dic["oldpassword"] # old password from the client 
            if token is not None and database_helper.check_valid_token(token): # checks if there are a valid token 
                    email = database_helper.get_email_from_token(token) 
                    password = database_helper.get_password_from_email(email) # the hashed password from db  
                    if not password: # if we do not have a password it's a google account 
                        return jsonify({"success":False, "message": "cant change google password"}), 401
                    if bcrypt.check_password_hash(password, oldPassword): # correct old password 
                        newPassword = bcrypt.generate_password_hash(json_dic["newpassword"]).decode("utf-8") # hashes and salts the new password 
                        db = database_helper.update_password(newPassword, email, password) # updates the new password 
                        if db:
                            return jsonify({"success":True,"message": "Successfully changed password"}), 200
                        else:
                            return jsonify({"success":False,"message": "Something went wrong"}), 500 # db crash 
                    else:
                        return jsonify({"success":False,"message": "Incorrect old password"}), 401 # wrong password 
            else:
                return jsonify({"success":False, "message": "Invalid token"}), 401 # not logged in 
        else:
            return jsonify({"success":False, "message": "data missing"}), 400 # missing data 
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403

@app.route("/sign_out", methods=["DELETE"])
def sign_out():
    token = request.headers.get('Authorization')

    #data = request.data
    hmac_resp = request.headers.get("X-HMAC")
    timestamp = request.headers.get("X-TIMESTAMP")
    if valid_hmac(token.encode(),hmac_resp,timestamp):
        if token is not None and database_helper.check_valid_token(token): # valid token 
            close_websocket(token) # closing websocket 
            signout = database_helper.delete_from_tokens(token) # deleting token from db 
            if signout:
                return jsonify({"success":True,"message": "Successfully signed out"}), 200 # success 
            else:
                return jsonify({"success":False,"message": "Something went wrong"}), 500 # db crash 
        elif token is None:
            return jsonify({"success":False, "message": "Token not found"}), 404 # token missing 
        else:
            return jsonify({"success":False, "message": "Invalid token"}), 401 # not logged in 
    else:
        return jsonify({"success":False,"message": "Method not allowed"}), 403

def not_missing_fields(json_dic, field_desc): # if thre are text and not null in all fealds 
    all_exists = True
    for val in field_desc:
            all_exists *=  json_dic[val] != None
    return all_exists
    
def validate_emails(email):
    try:
        # Check that the email address is valid. Turn on check_deliverability
        # for first-time validations like on account creation pages (but not
        # login pages).
        emailinfo = validate_email(email, check_deliverability=False)
        email = emailinfo.normalized
        return True

    except EmailNotValidError as e:
        print(str(e))
        return False


# Check that you can regenerate the same hmac and that the data is not too old
def valid_hmac(data, hmac_resp, timestamp):
    print("Client HMAC: ",hmac_resp)
    new_hmac = hmac.new(hmac_secret, (data.decode()+timestamp).encode(), hashlib.sha256).hexdigest() # Calc hmac the same way as on client
    print("Server HMAC: ",new_hmac) 

    ts_ttl = 15*60*1000 # Timestamp time-to-live. Not older than 15 min(in ms)
    timestamp = int(timestamp)
    curr_ts = int(time.time()*1000)
    print("Message transit time",curr_ts - timestamp)
    if hmac_resp == new_hmac and curr_ts - timestamp < ts_ttl: # Old and new hmac are the same and timestamp is not older than defined ttl
        return True
    else:
        return False


if __name__ == "__main__":
    app.debug = True
    #app.register_blueprint(app_blueprint)
    #app.register_blueprint(auth, url_prefix="/auth")
    app.run(port = 5001)

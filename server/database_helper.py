
# Terminal commands
# sqlite3 database.db < database.schema
# source bin/activate
# CRUD operations - create read update delete

# AC - application context
# RC - request context
# Environments for data
# Each request has its own context

import sqlite3
from flask import g
import secrets

database_uri = "database.db"

def get_db():
    db = getattr(g, "db", None) # check in context if db exist else return none
    if db is None:
        db = g.db = sqlite3.connect(database_uri)
    return db

def disconnect_db():
    db = getattr(g, "db", None)
    if db is not None:
        g.db.close()
        g.db = None
        
def insert_into_users(email, password, firstname, familyname, gender, city, country): # new user
    try:
        get_db().execute("insert into users values(?, ?, ?, ?, ?, ?, ?);", [email, password, firstname, familyname, gender, city, country])
        get_db().commit()
        return True
    except Exception as e:
        print(e)
        return False
   
def insert_into_tokens(email):
    try:
        logged_in = get_db().execute("SELECT email FROM tokens WHERE email LIKE ?;", [email])
        token = secrets.token_urlsafe(32) # create a random token with 32 len
        if logged_in.fetchall():# if we have a loged in user update 
            get_db().execute("UPDATE tokens SET token=(?) WHERE email=(?);", [token,email])
            get_db().commit()
        else:# new user just insert 
            get_db().execute("insert into tokens values(?, ?);", [email, token])
            get_db().commit()
        return token
    except Exception as e:
        print(e)
        return False
    
def insert_google_into_tokens(email, token):
    try:
        logged_in = get_db().execute("SELECT email FROM tokens WHERE email LIKE ?;", [email])
        if logged_in.fetchall():  # Updates tokens instead if already logged in 
            get_db().execute("UPDATE tokens SET token=(?) WHERE email=(?);", [token,email])
            get_db().commit()
        else: # new user just insert 
            get_db().execute("insert into tokens values(?, ?);", [email, token])
            get_db().commit()
        return token
    except Exception as e:
        print(e)
        return False
    
def insert_into_posts(emailto, emailfrom, message): # create a new post 
    try:
        get_db().execute("insert into posts (emailto, emailfrom, message) values(?, ?, ?);", [emailto, emailfrom, message])
        get_db().commit()
        return True
    except Exception as e:
        print(e)
        return False
    
    
def check_valid_token(token): # valid token
    try:
        dbtoken = get_db().execute("SELECT token FROM tokens WHERE token LIKE ?;", [token])
        dbtoken = dbtoken.fetchall()
        if dbtoken:
            return True
        else:
            return False   
    except Exception as e:
        print(e)
        return False
    
def check_valid_email(email): # valid email from a email
    try:
        dbemail = get_db().execute("SELECT email FROM users WHERE email LIKE ?;", [email])
        if dbemail.fetchall():
            return True
        else:
            return False
    except Exception as e:
        print(e)
        return False

def check_password_from_users(email, password): #  not in use 
    try:
        dbpass = get_db().execute("SELECT password FROM users WHERE email like ? and password like ?;", [email, password])
        dbpass = dbpass.fetchall()
        if dbpass:
            return True
        else:
            return False    
    except Exception as e:
        print(e)
        return False
    
def get_email_from_token(token): # get email from a token 
    try:
        dbemail = get_db().execute("SELECT email FROM tokens WHERE token LIKE ?;", [token])
        dbemail = dbemail.fetchall()
        if dbemail:
            return dbemail[0][0]
        else:
            return False   
    except Exception as e:
        print(e)
        return False
    
def get_userdata(email): # get all the data from a user in the db view 
    try:
        cursor = get_db().execute("SELECT * FROM userdata WHERE email LIKE ?;", [email]) # + variable here causes sql injection
        return cursor_to_list(cursor)
    except Exception as e:
        print(e)
        return False
    
def get_password_from_email(email): # returns the password from a user 
    try:
        dbpass = get_db().execute("SELECT password FROM users WHERE email like ?;", [email])
        dbpass = dbpass.fetchall()
        if dbpass:
            #print(dbpass[0][0])
            return dbpass[0][0]
        else:
            return False    
    except Exception as e:
        print(e)
        return False

def get_user_data_by_token(token): #not in use 
    try:
        dbemail = get_email_from_token(token)
        if dbemail:    
            dbdata = get_db().execute("SELECT * FROM userdata WHERE email=(?);", [dbemail])
            dbdata = dbdata.fetchall()
            if dbdata:
                return cursor_to_list(dbdata)
        return False
    except Exception as e:
        print(e)
        return False
    
def get_user_data_by_email(email,token): # not in use 
    try:
        if get_email_from_token(token):
            dbemail = get_db().execute("SELECT * FROM tokens WHERE token=(?);", [email])
            if dbemail:    
                return cursor_to_list(dbemail)
        return False
    except Exception as e:
        print(e)
        return False
    
def get_user_messages_by_token(token): # not in use 
    try:
        dbemail = get_email_from_token(token)
        if dbemail:
            dbmessages = get_db().execute("SELECT message,emailfrom FROM posts WHERE emailto=(?);", [dbemail])
            if dbmessages.fetchall():
                return cursor_to_list(dbmessages)
        return False
    except Exception as e:
        print(e)
        return False
    
def get_user_messages_by_email(email): # get the messages from a given email 
    try:
        dbdata = get_db().execute("SELECT * FROM posts WHERE emailto=(?);", [email])
        return cursor_to_list(dbdata)
    except Exception as e:
        print(e)
        return False
    

def delete_from_tokens(token): # delete a token 
    try:
        get_db().execute("DELETE FROM tokens WHERE token=(?);", [token])
        get_db().commit()
        return True      
    except Exception as e:
        print(e)
        return False

def update_password(newPassword, email, oldPassword): # update a passwordhash  
    try:
        get_db().execute("UPDATE users SET password=(?) WHERE email=(?) AND password=(?);", [newPassword, email, oldPassword])
        get_db().commit()  
        return True 
    except Exception as e:
        print(e)
        return False
    
def cursor_to_list(cursor): # gets the elements from the cb cursor to an list
    rows = cursor.fetchall()
    result = []
    curs_desc = cursor.description
    cursor.close()
    for index in range(len(rows)):
        dict = {}
        for cur_index in range(len(curs_desc)):
            dict[curs_desc[cur_index][0]] = rows[index][cur_index]
        result.append(dict)
    return result
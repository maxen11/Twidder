create table users(email varchar(100), password varchar(100), firstname varchar(100), familyname varchar(100), gender varchar(100), city varchar(100), country varchar(100), PRIMARY KEY(email));
create table tokens(email varchar(100), token varchar(256), PRIMARY KEY(token));
create table posts(emailto varchar(100), emailfrom varchar(100), message varchar(100), postid INTEGER PRIMARY KEY AUTOINCREMENT);
CREATE VIEW userdata AS SELECT email,firstname,familyname,gender,city,country FROM users; 
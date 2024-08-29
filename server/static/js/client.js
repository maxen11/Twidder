
// After loading logic for displaying correct views and urls
window.onload = function() {
    if(localStorage.getItem("token") !== null){ // have a token
        establish_websocket(); // make a websocket
        profileview(); // change the view to logged in 
        handleLocation(); // change the location to the browser path 
    }else if(check_google_token()){ // load a token if have a sign in with google 
        establish_websocket();
        profileview();
        handleLocation();
    }else {
        welcomeview(); // default behaviur if not logegd in 
    } 
};

const hmac_secret = 's3cr3tk3y';

// Sets the correct path in the url
function handleLocation(){
        var path = window.location.pathname; // get path
        var paths = ["/home", "/Browse", "/Account"]; // Accepted paths 
        if(paths.includes(path)){
            tab(event ,path.slice(1)); // display the path 
        }else {
            document.getElementById("home_btn").click(); // Default ation if path non valid home
        }
}

// listener when the history button is activated, back-forward arrow
window.addEventListener("popstate", (event) => { 
    if(localStorage.getItem("token") !== null){ // no loopback to profile view if logged out through history
        handleLocation();
    }
  });
  
//Checks token validity from cookie and puts in localStorage
function check_google_token(){
    token = getCookie("access_token") // get the token from within the cookie sent from the sever
    if (token !== null){
        localStorage.setItem("token", token); // set token 
        console.log("Signin success for user with google.");
        return true;
    }
    return false;
}

// Gets cookie value based on name
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';'); // Splits the cookie data into parts
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) { // checks if the token data is there. 
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1)); // seperating the name from the data we want 
                break;
            }
        }
    }
    return cookieValue;
}

//Displays the welcome view, loads html welcome view
function welcomeview(){ // landing page 
        var viewToLoad = "welcomeview"; 
        var viewHTML = document.getElementById(viewToLoad).innerHTML; // load html code 
        document.getElementById("content").innerHTML = viewHTML;

        // Checks if history state is not the same you're trying to change to. Only change if different 
        if(history.state && history.state.page !== "/welcome"){
            history.pushState({page: "welcome"}, "", "/"+"welcome");
            document.title = "Twidder/"+"welcome";
        }else if(!history.state){
            history.pushState({page: "welcome"}, "", "/home");
            document.title = "Twidder/"+"welcome";
        }
}

// Signs in user with post request to server. If successful it stores a token and esablishes a websocket for auto logout.
// On error response from server it displays error message on form.
function signIn(){
    var email = document.getElementById("signin_Email");
    var signin_password = document.getElementById("signin_password");

    var signinform ={ // make a json object 
        username: email.value,
        password: signin_password.value
    };

    var timestamp = +new Date();
    var data = signinform;//+timestamp;
    var hmac = CryptoJS.HmacSHA256(JSON.stringify(data)+timestamp, hmac_secret).toString();

    var request = new XMLHttpRequest(); // start a http post request to the server 
    request.open("POST", "/sign_in", true);
    request.onreadystatechange = function(){
        if (this.readyState == 4 ){ // only if the request is done from the server 
            var signin = JSON.parse(request.responseText); // recived data 
            
            email.setCustomValidity(""); // custom error print to the client 
            if(signin["success"]){ // no error code from the server 
                data = signin["data"];
                localStorage.setItem("token", data); // set token 
                console.log("Signin success for user "+email+".");
                document.getElementById("Signinform").reset(); // sets blanks fealds in the data 

                //WEBSOCKETS HERE
                establish_websocket(); // create a websocket with the serveer

                profileview(); // change view to the loged in 
                document.getElementById("home_btn").click(); // defalut view /home 
            } else if(!signin["success"]){ // error state from the server 
                console.log(signin["message"]);
                switch(request.status){
                    case 401:
                        email.setCustomValidity("Incorrect username or password! Please try again");
                        break;
                    case 400:
                        email.setCustomValidity("Data missing, did you fill in all required fields?");
                        break;
                    default:
                        console.log("Unexpected error trying to login in. Status code: "+request.status);
                        break;
                }
            }
        }
    }
    request.setRequestHeader("Content-Type","application/json;charset=UTF-8"); // the send header 
    request.setRequestHeader("X-HMAC", hmac);
    request.setRequestHeader("X-TIMESTAMP", timestamp);
    request.send(JSON.stringify(data)); // the sent xml data to the server  
}

// Changes window to /login_google. Triggers google login. Is called with html onclick. 
function login_google(){
    window.location.href = '/login_google'; // google auth login page 
}

// Websocket to server used for storing login session on server-side. Used for automatic logout 
// if logging in from another browser and terminating old connection.
function establish_websocket(){
    var socket = new WebSocket("wss://"+location.host+"/ws_connect");
    socket.onopen = function() { // Sends token when websocket opens.
            var token = localStorage.getItem("token");
            console.log(token);
            console.log("Successfully opened websocket.");
            socket.send(token);
    };
    // Log errors
    socket.onerror = function (error) {
        console.log('WebSocket Error ' + error);
    };
    // Log messages from the server
    socket.onmessage = function (e) {
            console.log('Server: ' + e.data);
            if(e.data == "False"){ // Close connection and remove token when server sends False. (Auto logout)
                console.log("Closed websocket connection to server.")
                socket.close();
                localStorage.removeItem("token");
                welcomeview();
            } 
    };
}

// Signs up user by posting user info to be stored on serverside database. 
// Contains validity checking for password, email and displays other error messages
// from server on the html form.
function signUp(){
    if(passwordValidation("signup_password", "repeat_password")){
        var inputObject = {
            email: document.getElementById("signup_Email").value,
            firstname: document.getElementById("signup_FirstName").value,
            gender: document.getElementById("signup_Gender").value,
            familyname: document.getElementById("signup_FamilyName").value,
            city: document.getElementById("signup_City").value,
            password: document.getElementById("signup_password").value,
            country: document.getElementById("signup_Country").value
        };
        var timestamp = +new Date();
        var data = inputObject;//+timestamp;
        var hmac = CryptoJS.HmacSHA256(JSON.stringify(data)+timestamp, hmac_secret).toString();


        var request = new XMLHttpRequest();
        request.open("POST", "/sign_up", true);
        request.onreadystatechange = function(){
            if (this.readyState == 4 ){
                var signup = JSON.parse(request.responseText);
                if(signup["success"]){
                    console.log("Signup success for user "+inputObject.email+".")
                    document.getElementById("Signupform").reset();
                } else if(!signup["success"]){
                    switch (request.status){
                        case 409:
                            document.getElementById("signup_Email").setCustomValidity("User already exsits! Try again!");
                            break;
                        case 500:
                            console.log("Something went wrong at the serverside!");
                            break;
                        case 400:
                            if(signup["message"] =="missing email"){
                                document.getElementById("signup_Email").setCustomValidity("No email given! Please try again!");
                            }else if(signup["message"] =="invalid email"){
                                document.getElementById("signup_Email").setCustomValidity("Incorrect email format! Try again!");
                            }else if(signup["message"] =="data missing"){
                                document.getElementById("signup_Email").setCustomValidity("Make sure all required fields are filled!");
                            }
                            break;
                        default:
                            console.log("Unexpected error trying to sign up. Status code "+request.status);
                            break;
                    }
                    console.log("Failed to sign up.");
                }
            }
        }
        request.setRequestHeader("X-HMAC", hmac);
        request.setRequestHeader("X-TIMESTAMP", timestamp);
        request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
        request.send(JSON.stringify(inputObject));
    }
}

// Validity checker for password. Checks length and if two passwords are equal, if not valid
// it displays error message on html form.
function passwordValidation(passwordId, repeat_passId){
    var password = document.getElementById(passwordId);
    var repeat_pass = document.getElementById(repeat_passId);

    password.setCustomValidity("");
    repeat_pass.setCustomValidity("");
    var pass_length = 8;
    if(password.value.length < pass_length){
        password.setCustomValidity("Password must be at least "+pass_length+" characters");
        return false;
    }
    else if(password.value != repeat_pass.value){
        repeat_pass.setCustomValidity("Passwords do not match.");
        return false;
    } 
    return true;
}

// Loads the profile html view
function profileview(){
    var viewToLoad = "profileview"; 
    var viewHTML = document.getElementById(viewToLoad).innerHTML;
    document.getElementById("content").innerHTML = viewHTML;
    loadHome();
}

// Method for changing password. Does password validation(length, equal). Uses POST for sending
// to server. Displays error message on html form on error response from server.
function changePassword(){
    var changePasswordForm = document.getElementById("changePasswordForm");
    var oldPassword = document.getElementById("old_password");
    var newPassword = document.getElementById("new_password");
    oldPassword.setCustomValidity("");

    
    if(passwordValidation("old_password", "old_password") && passwordValidation("new_password", "repeat_new_password")){
        var changePassData = {
            oldpassword: oldPassword.value,
            newpassword: newPassword.value
        }
        var token = localStorage.getItem("token");
        var request = new XMLHttpRequest();
        var timestamp = +new Date();
        var data = changePassData;//+timestamp;
        var hmac = CryptoJS.HmacSHA256(JSON.stringify(data)+timestamp, hmac_secret).toString();

        request.open("PUT", "/change_password", true);
        request.onreadystatechange = function(){

            if (this.readyState == 4 ){
                var changePassword = JSON.parse(request.responseText);
                if(changePassword["success"]){
                    console.log(changePassword["message"]);
                    changePasswordForm.reset();
                } else if(!changePassword["success"]){
                    console.log(changePassword["message"]);
                    switch(request.status){
                        case 401:
                            if (changePassword["message"]==  "Incorrect old password"){
                                oldPassword.setCustomValidity(changePassword["message"]+"! Please try again!");
                            }else if(changePassword["message"]=="Invalid token"){
                                console.log("Invalid token.")
                            }
                            break;
                        case 500:
                            console.log("Something went wrong at the serverside")
                            break;
                        case 400:
                            oldPassword.setCustomValidity("Data missing somewhere, check that all fields are filled!");
                            break;
                        default:
                            console.log("Unexptected error. Status code: "+request.status);
                            break;
                    }
                }
            }
        }
        request.setRequestHeader("X-HMAC", hmac);
        request.setRequestHeader("X-TIMESTAMP", timestamp);
        request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
        request.setRequestHeader("Authorization", token);
        request.send(JSON.stringify(changePassData));
    }
}

// Signs out user. Sends token to server with DELETE which deletes the token from websocket connection and database
// On error response from server only a log message it displayed. On success it changes view to welcome view.
function signOut(){
    var token = localStorage.getItem("token");
    var timestamp = +new Date();
    var hmac = CryptoJS.HmacSHA256(token+timestamp, hmac_secret).toString();

    var request = new XMLHttpRequest();
    request.open("DELETE", "/sign_out", true);
    request.onreadystatechange = function(){
        if (this.readyState == 4 ){
            var msg = JSON.parse(request.responseText);
            if(msg["success"]){
                localStorage.removeItem("token");
                console.log("Signout success.");
                welcomeview();
            } else {
                switch(request.status){
                    case 404:
                        console.log("No token was found, maybe it was deleted?");
                        break;
                    case 500:
                        console.log("Something went wrong at the serverside trying to signout");
                        break;
                    case 401:
                        console.log("An invalid token was used trying to sign out.");
                        break;
                    default:
                        console.log("Unexpected error when trying to sign out. Status code: "+request.status);
                        break;
                }
            }
        }
    }
    request.setRequestHeader("X-HMAC", hmac);
    request.setRequestHeader("X-TIMESTAMP", timestamp);
    request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
    request.setRequestHeader("Authorization", token);
    request.send();
}

// Loads the home page with userdata and their posts. 
function loadHome(){
    //window.history.pushState({},"", "/Home");
    getuserdata("profile", null);
    loadPosts("profile");
}

// Readies a post message to be sent to server and sends it. Does some validation for empty posts. 
function makePost(page){
    var text = document.getElementById(page+"_postTextarea");
    if (text.value.trim().length===0) {
        text.setCustomValidity("Text cant be empty");
        console.log('str is empty!');
    }else{
        var emailTo;
        if (page === "Browse"){
            emailTo = sessionStorage.getItem("searchEmail");
        }else {
            emailTo = null;
        }
        
        post_data = {
            email: emailTo,
            message: text.value
        }
        
        var token = localStorage.getItem("token");
        var timestamp = +new Date();
        var data = post_data;//+timestamp;
        var hmac = CryptoJS.HmacSHA256(JSON.stringify(data)+timestamp, hmac_secret).toString();

        var request = new XMLHttpRequest();
        request.open("POST", "/post_message", true);
        request.onreadystatechange = function(){
            if (this.readyState == 4 ){
                var msg = JSON.parse(request.responseText);
                if(msg["success"]){
                    console.log(msg["message"]);
                } else {
                    switch(request.status){
                        case 500:
                            console.log("Something went wrong on the server side trying to create post.");
                            break;
                        case 404:
                            console.log("Email not found for creating post.");
                            break;
                        case 400:
                            console.log("Data is missing, are all required fields filled?")
                            break;
                        default:
                            console.log("Unexpected error creating a post. Status code: "+request.status);
                            break;
                    }
                }
            }
        }
        request.setRequestHeader("X-HMAC", hmac);
        request.setRequestHeader("X-TIMESTAMP", timestamp);
        request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
        request.setRequestHeader("Authorization", token);
        request.send(JSON.stringify(post_data));
    }
    
    text.value = "";
    loadPosts(page, emailTo);
    return false;
}

// Requests userdata from server through email or token.
function getuserdata(page,email){
    var userdata;
    var token = localStorage.getItem("token");
    var timestamp = +new Date();
    var hmac = CryptoJS.HmacSHA256(token+timestamp, hmac_secret).toString();

    let request = new XMLHttpRequest();
    if(email !== null){
        request.open("GET", "/get_user_data_by_email/" + email.value, true);
    }else{
        request.open("GET", "/get_user_data_by_token", true);
    }
    request.onreadystatechange = function(){
        if (request.readyState == 4){
            userdata = JSON.parse(request.responseText);
            if(userdata["success"]){
                printuserdata(page,userdata);
            } else{
                switch(request.status){
                    case 404:
                        console.log("Email not found for getting userdata");
                        break;
                    case 400:
                        console.log("Data missing, are all required fields filled?");
                        break;
                    case 401:
                        console.log("Invalid token");
                        break;
                    default:
                        console.log("Unexpected error getting userdata. Status code: "+request.status);
                        break;
                }
            }
        }
    }
    request.setRequestHeader("X-HMAC", hmac);
    request.setRequestHeader("X-TIMESTAMP", timestamp);
    request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
    request.setRequestHeader("Authorization", token);
    request.send();
}

// Creates html for userdata
function printuserdata(page,userdata){    
    var firstName = document.getElementById(page+"_firstName");
    var familyName = document.getElementById(page+"_familyName");
    var gender = document.getElementById(page+"_gender");
    var city = document.getElementById(page+"_city");
    var country = document.getElementById(page+"_country");
    var email = document.getElementById(page+"_email");
    firstName.innerHTML = "<div class='row'> First Name: " +userdata["data"]["firstname"] + "</div>";
    familyName.innerHTML = "<div class='row'> Family Name: " +userdata["data"]["familyname"] + "</div>";
    gender.innerHTML = "<div class='row'> Gender: " +userdata["data"]["gender"] + "</div>";
    city.innerHTML = "<div class='row'> City: " +userdata["data"]["city"] + "</div>";
    country.innerHTML = "<div class='row'> Country: " +userdata["data"]["country"] + "</div>";
    email.innerHTML = "<div class='row'> Email: " +userdata["data"]["email"] + "</div>";
}

// Gets posts through email(Browse search) or token(home page). Makes a GET request to server.
function loadPosts(page){
    var posts;
    var token = localStorage.getItem("token");
    var timestamp = +new Date();
    var hmac = CryptoJS.HmacSHA256(token+timestamp, hmac_secret).toString();

    let request = new XMLHttpRequest();
    if(page === "Browse"){
        var email = sessionStorage.getItem("searchEmail");
        request.open("GET", "/get_user_messages_by_email/" + email, true);
    }else{
        request.open("GET", "/get_user_messages_by_token", true);
    }
    request.onreadystatechange = function(){
        if (request.readyState == 4){
            posts = JSON.parse(request.responseText);
            if(posts["success"]){
                printmesseges(page,posts,posts["emailto"]);
            } else{
                switch(request.status){
                    case 404:
                        console.log("Email not found for getting posts");
                        break;
                    case 400:
                        console.log("Data missing, are all required fields filled?");
                        break;
                    case 401:
                        console.log("Invalid token");
                        break;
                    case 500:
                        console.log("Something went wrong at the serverside!");
                        break;
                    default:
                        console.log("Unexpected error getting posts. Status code: "+request.status);
                        break;
                }
            }
        }
    }
    request.setRequestHeader("X-HMAC", hmac);
    request.setRequestHeader("X-TIMESTAMP", timestamp);
    request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
    request.setRequestHeader("Authorization", token);
    request.send();
}

// Inserts html elements in inside a users post wall with their messages.
// Gets nr of posts from sessionstorage and refreshes and adds newly added posts.
// First removes all child elements of wall and then adds them anew where the new posts now will be added
function printmesseges(page,posts,email){
    if(posts["success"]){
        var nr_curr_posts = posts["data"].length;
        var nr_new_posts = nr_curr_posts;
        var nr_old_posts = 0;
        if(sessionStorage.getItem(email+"wallLength") !== null){
            nr_old_posts = parseInt(sessionStorage.getItem(email+"wallLength"));
            nr_new_posts = nr_curr_posts - nr_old_posts;
        }
        var postWall = "";
        var parent = document.getElementById(page+"_postWall");
        while(parent.firstChild){
            parent.removeChild(parent.firstChild);
        }
        for (var i = nr_curr_posts-1; i>=0 ; i--){
            postWall = "<div class='post'> <div class='post_writer'>Posted by: "+posts["data"][i]["emailfrom"]+"</div>"+ "<div class='post_content' >" + posts["data"][i]["message"] + "</div></div>" + postWall;
        }
        sessionStorage.setItem(email+"wallLength", nr_curr_posts);

        document.getElementById(page+"_postWall").insertAdjacentHTML('beforeend', postWall);
    }
}

// Changes what is displayed inside profile view and makes pages in the navbar active
// Sets everything first to diplay none and removes active tag in the classnames which highlights
// current tab active. Then it makes the current chosen one active by making it green and setting
// its content style to display block. It also handles history wich back/forward buttons.

function tab(event, nav_option){
    var elements = document.getElementsByClassName("tabcontent");
    var btns = document.getElementsByClassName("tablinks");
    for(i = 0; i<elements.length;i++){
        elements[i].style.display = "none";
    }
    for(i = 0; i<btns.length;i++){
        btns[i].className = btns[i].className.replace(" active", "");
    }
    
    // Adds to history of the next content to be viewed if its not the same as the one previously.
    if(history.state && history.state.page !== nav_option){
        history.pushState({page: nav_option}, "", "/"+nav_option);
        document.title = "Twidder/"+nav_option;
    }else if(!history.state){
        history.pushState({page: "home"}, "", "/home");
        nav_option = "home";
    }

    var curr_element =  document.getElementById(nav_option+"_btn");
    var curr_element2 =  document.getElementById(nav_option);
 
    curr_element2.style.display = "block";
    curr_element2.style.backgroundcolor = "green";
    //event.currentTarget.className += " active";
    curr_element.className += " active";
}

// Handles the searchbar in the browse tab. 
// Makes a GET request to the server to get userdata.
// Dispays error on the form on response error from server
// On successful requests the userdata for the searched user is displayed.
function browseSearch(){
    var email = document.getElementById("searchInput");
    var userdata;
    var token = localStorage.getItem("token");
    if(email.value !== ""){
        var timestamp = +new Date();
        var hmac = CryptoJS.HmacSHA256(token+timestamp, hmac_secret).toString();

        let request = new XMLHttpRequest();
        request.open("GET", "/get_user_data_by_email/" + email.value, true);
        request.onreadystatechange = function(){
            if (request.readyState == 4){
                userdata = JSON.parse(request.responseText);
                var element = document.getElementById("searchProfile");

                var searchBar = document.getElementById("searchBar");
                console.log("Email exists in search: "+userdata["success"] + "  " + email.value);
                email.setCustomValidity("");
            
                if(!userdata["success"]){
                    element.style.display = "none";
                    console.log(userdata["message"]);
                    switch(request.status){
                        case 404:
                            email.setCustomValidity("Email does not exist.");
                            break;
                        case 400:
                            email.setCustomValidity("Data missing, are all required fields filled?");
                            break;
                        case 401:
                            console.log("Invalid token");
                            break;
                        default:
                            email.setCustomValidity("Unexpected error getting for search. Status code: "+request.status);
                            break;
                    }
                }else{
                    element.style.display = "block";
                    sessionStorage.setItem("searchEmail", email.value);
                    printuserdata("Browse",userdata);
                    loadPosts("Browse");
                    email.value = "";
                }
            }

        }
        request.setRequestHeader("X-HMAC", hmac);
        request.setRequestHeader("X-TIMESTAMP", timestamp);
        request.setRequestHeader("Content-Type","application/json;charset=UTF-8");
        request.setRequestHeader("Authorization", token);
        request.send();
    }
    
}

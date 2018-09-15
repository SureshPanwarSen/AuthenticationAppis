# AuthenticationAppis
Authentication api's with login, register, reset password and forgot api's using passport.js and nodemailer 

# Clone Project
git clone https://github.com/SureshPanwarSen/AuthenticationAppis.git
 
# Setup Enviromnent file
.env

# install packages using 
npm install

# run Server
nodemon app

# SignUp
Method: POST
URL:== http://localhost:3000/signup
body:== {
   "email": "email",
    "password": "pass1",
    "confirmPassword": "pass2"
}

# login
Method:== POST
URL:== http://localhost:3000/login
body:== {
   "email": "email",
    "password": "pass"
}

# updatePassWord
Method:== POST
URL:== http://localhost:3000/updatepassword
body:== {
    "password": "newpassword",
    "confirmPassword": "newpassword"
}

# forgot Password Toeken Generator
Method:== POST
URL:== http://localhost:3000/forgot
body:== {
    "email": "Registered Email"
}

# forgot Password Toeken verification 
# and new password generating
Method:== POST
URL:== http://localhost:3000/reset/:token
body:== {
    "password": "pass1",
    "confirmPassword": "pass2"
}

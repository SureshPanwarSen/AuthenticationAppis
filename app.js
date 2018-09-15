const express = require('express');
const compression = require('compression');
const session = require('express-session');
const bodyParser = require('body-parser');
const logger = require('morgan');
const errorHandler = require('errorhandler');
const dotenv = require('dotenv');
const MongoStore = require('connect-mongo')(session);
const flash = require('express-flash');
const path = require('path');
const mongoose = require('mongoose');
const passport = require('passport');
const expressValidator = require('express-validator');
const expressStatusMonitor = require('express-status-monitor');
const ip = require('ip');

dotenv.load({
    path: '.env'
});

const userController = require('./controllers/user');

const passportConfig = require('./config/passport');

const app = express();

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true
});
mongoose.connection.on('error', (err) => {
    console.error(err);
    process.exit();
});

app.set('host', process.env.OPENSHIFT_NODEJS_IP || '0.0.0.0');
app.set('port', process.env.PORT || process.env.OPENSHIFT_NODEJS_PORT || 3000);
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');
app.use(expressStatusMonitor());
app.use(compression());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(expressValidator());
app.use(session({
    resave: true,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
    cookie: {
        maxAge: 100000
    },
    store: new MongoStore({
        url: process.env.MONGODB_URI,
        autoReconnect: true,
    })
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use((req, res, next) => {
    res.locals.user = req.user;
    next();
});

app.use('/', express.static(path.join(__dirname, 'public'), {
    maxAge: 31557600000
}));

app.post('/login', userController.postLogin);
app.get('/logout', userController.logout);
app.post('/forgot', userController.postForgot);
app.post('/reset/:token', userController.postReset);
app.post('/signup', userController.postSignup);
app.post('/updatepassword', passportConfig.isAuthenticated, userController.postUpdatePassword);

if (process.env.NODE_ENV === 'development') {
    app.use(errorHandler());
} else {
    app.use(function (err, req, res, next) {
        console.error(err);
        res.status(500).send('Server Error');
    });
}

app.listen(app.get('port'), () => {
    console.log("Node Server is listening on http://" + ip.address() + ":" + app.get('port'));
});

module.exports = app;
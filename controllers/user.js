const {
    promisify
} = require('util');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const User = require('../models/user');

const randomBytesAsync = promisify(crypto.randomBytes);

/**
 * POST /login
 * Sign in using email and password.
 */
exports.postLogin = (req, res, next) => {
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('password', 'Password cannot be blank').notEmpty();
    req.sanitize('email').normalizeEmail({
        gmail_remove_dots: false
    });

    const errors = req.validationErrors();

    if (errors) {
        req.flash('errors', errors);
        return res.status(401).json('LogIn failed');
    }

    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            req.flash('errors', info);
            return res.status(401).json('LogIn failed, User Not found');
        }
        req.logIn(user, (err) => {
            if (err) {
                return next(err);
            }
            req.flash('success', {
                msg: 'Success! You are logged in.'
            });
            return res.status(200).json('LogIn successful');
        });
    })(req, res, next);
};

/**
 * GET /logout
 * Log out.
 */
exports.logout = (req, res) => {
    req.logout();
    req.session.destroy((err) => {
        if (err) console.log('Error : Failed to destroy the session during logout.', err);
        req.user = null;
        res.status(200).json(true);
    });
};

/**
 * POST /signup
 * Create a new local account.
 */
exports.postSignup = (req, res, next) => {
    req.assert('email', 'Email is not valid').isEmail();
    req.assert('password', 'Password must be at least 4 characters long').len(4);
    req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);
    req.sanitize('email').normalizeEmail({
        gmail_remove_dots: false
    });

    const errors = req.validationErrors();

    if (errors) {
        req.flash('errors', errors);
        res.status(422).json('Validation error, Please enter values in correct requried format.')
    }

    const user = new User({
        email: req.body.email,
        password: req.body.password
    });

    User.findOne({
        email: req.body.email
    }, (err, existingUser) => {
        if (err) {
            return next(err);
        }
        if (existingUser) {
            res.status(201).json('Account with that email address already exists.');
        }
        user.save((err) => {
            if (err) {
                return next(err);
            }
            req.logIn(user, (err) => {
                if (err) {
                    return next(err);
                }
                res.status(200).json('Signup successfull');
            });
        });
    });
};

/**
 * POST /account/password
 * Update current password.
 */
exports.postUpdatePassword = (req, res, next) => {
    req.assert('password', 'Password must be at least 4 characters long').len(4);
    req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

    const errors = req.validationErrors();

    if (errors) {
        req.flash('errors', errors);
        return res.status(401).json('Password updation failed, validation errors, Please enter in given format');
    }

    User.findById(req.user.id, (err, user) => {
        if (err) {
            return next(err);
        }
        user.password = req.body.password;
        user.save((err) => {
            if (err) {
                return next(err);
            }
            req.flash('success', {
                msg: 'Password has been changed.'
            });
            return res.status(200).json('Password updated');
        });
    });
};

/**
 * GET /reset/:token
 * Reset Password page.
 */
exports.getReset = (req, res, next) => {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    User
        .findOne({
            passwordResetToken: req.params.token
        })
        .where('passwordResetExpires').gt(Date.now())
        .exec((err, user) => {
            if (err) {
                return next(err);
            }
            if (!user) {
                req.flash('errors', {
                    msg: 'Password reset token is invalid or has expired.'
                });
                return res.redirect('/forgot');
            }
            res.render('account/reset', {
                title: 'Password Reset'
            });
        });
};

/**
 * POST /reset/:token
 * Process the reset password request.
 */
exports.postReset = (req, res, next) => {
    req.assert('password', 'Password must be at least 4 characters long.').len(4);
    req.assert('confirm', 'Passwords must match.').equals(req.body.password);

    const errors = req.validationErrors();

    if (errors) {
        return res.status(401).json('Errors with validation.');
    }

    const resetPassword = () =>
        User
        .findOne({
            passwordResetToken: req.params.token
        })
        .where('passwordResetExpires').gt(Date.now())
        .then((user) => {
            if (!user) {
                return res.status(404).json('Password reset token is invalid or has expired.');
            }
            user.password = req.body.password;
            user.passwordResetToken = undefined;
            user.passwordResetExpires = undefined;
            return user.save().then(() => new Promise((resolve, reject) => {
                req.logIn(user, (err) => {
                    if (err) {
                        return reject(err);
                    }
                    resolve(user);
                });
            }));
        });

    const sendResetPasswordEmail = (user) => {
        if (!user) {
            return;
        }
        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.SEND_USER,
                pass: process.env.SEND_PASSWORD
            }
        });
        const mailOptions = {
            to: user.email,
            from: process.env.SEND_USER,
            subject: 'App password changed',
            text: `Hello,\n\nThis is a confirmation that the password for your account ${user.email} has just been changed.\n`
        };
        return transporter.sendMail(mailOptions)
            .then(() => {
                res.status(200).json('Success! Your password has been changed.');
            })
            .catch((err) => {
                if (err.message === 'self signed certificate in certificate chain') {
                    console.log('WARNING: Self signed certificate in certificate chain. Retrying with the self signed certificate. Use a valid certificate if in production.');
                    transporter = nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: process.env.SEND_USER,
                            pass: process.env.SEND_PASSWORD
                        },
                        tls: {
                            rejectUnauthorized: false
                        }
                    });
                    return transporter.sendMail(mailOptions)
                        .then(() => {
                            res.status(200).json('Success! Your password has been changed.')
                        });
                }
                console.log('ERROR: Could not send password reset confirmation email after security downgrade.\n', err);
                return err;
            });
    };

    resetPassword()
        .then(sendResetPasswordEmail)
        .then(() => {
            if (!res.finished) res.status(200).json('');
        })
        .catch(err => next(err));
};

/**
 * POST /forgot
 * Create a random token, then the send user an email with a reset link.
 */
exports.postForgot = (req, res, next) => {
    req.assert('email', 'Please enter a valid email address.').isEmail();
    req.sanitize('email').normalizeEmail({
        gmail_remove_dots: false
    });

    const errors = req.validationErrors();

    if (errors) {
        res.status(200).json('errors in validation');
    }

    const createRandomToken = randomBytesAsync(16)
        .then(buf => buf.toString('hex'));

    const setRandomToken = token =>
        User
        .findOne({
            email: req.body.email
        })
        .then((user) => {
            if (!user) {
                res.status(404).json('Account with that email address does not exist.');
            }
            user.passwordResetToken = token;
            user.passwordResetExpires = Date.now() + 3600000;
            user = user.save();
            return user;
        });

    const sendForgotPasswordEmail = (user) => {
        if (!user) {
            return;
        }
        const token = user.passwordResetToken;
        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.SEND_USER, // login account from which we will send email links.
                pass: process.env.SEND_PASSWORD // password related to the email
            }
        });
        const mailOptions = {
            to: user.email,
            from: process.env.SEND_USER,
            subject: 'Reset your password on AuthenticationApp',
            text: `Please click on the following link, or paste this into your browser to complete the process:\n\n
        http://${req.headers.host}/reset/${token}\n\n`
        };
        return transporter.sendMail(mailOptions)
            .then(() => {
                res.status(200).json(`An e-mail has been sent to ${user.email} with further instructions.`);
            })
            .catch((err) => {
                if (err.message === 'self signed certificate in certificate chain') {
                    transporter = nodemailer.createTransport({
                        service: 'gmail',
                        auth: {
                            user: process.env.SEND_USER,
                            pass: process.env.SEND_PASSWORD
                        },
                        tls: {
                            rejectUnauthorized: false
                        }
                    });
                    return transporter.sendMail(mailOptions)
                        .then(() => {
                            res.status(200).json(`An e-mail has been sent to ${user.email} with further instructions.`);
                        });
                }
                console.log('ERROR: Could not send forgot password email after security downgrade.\n', err);
                // res.status(404).json('Error sending the password reset message. Please try again shortly.');
                return err;
            });
    };

    createRandomToken
        .then(setRandomToken)
        .then(sendForgotPasswordEmail)
        .catch(next);
};
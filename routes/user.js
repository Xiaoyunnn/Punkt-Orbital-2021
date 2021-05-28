// jshint esversion: 8
const express = require("express");
const router = express.Router();
const bodyParser = require("body-parser");
const ejs = require("ejs");
const $ = require('jquery');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const passwordValidator = require('password-validator');
const schema = new passwordValidator();
const User = require("../models/user");
const flash = require('express-flash');
const async = require("async");
const nodemailer = require("nodemailer");
const crypto = require("crypto");

schema
  .is().min(6) // Minimum length 6
  .is().max(50) // Maximum length 50
  .has().uppercase() // Must have uppercase letters
  .has().lowercase() // Must have lowercase letters
  .has().digits(1); // Must have at least 1 digits

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/punkt"
    // userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));
router.get("/", (req, res) => {
  res.render("home");
});

router.get("/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  }));

router.get("/auth/google/punkt",
  passport.authenticate("google", {
    failureRedirect: "/login"
  }),
  (req, res) => {
    // Successful authentication, redirect home.
    res.redirect("/dashboard");
  });

router.get("/login", (req, res) => {
  res.render("login", {
    loginErrors: []
  });
});

router.get("/signup", (req, res) => {
  res.render("signup", {
    loginErrors: []
  });
});

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

router.get("/failure", (req, res) => {
  res.render("failure");
});

router.get("/forgot-password", (req, res) => {
  res.render("forgot", {
    forgotErr: "",
    forgotSuccess: ""
  });
});

router.post("/signup", (req, res) => {

  if (!req.body.username || !req.body.displayName || !req.body.password || !req.body.password2) {
    req.flash("signupErr", "Please fill in all fields.");
    return res.redirect("/signup");
  } else if (req.body.password !== req.body.password2) {
    req.flash("signupErr", "Passwords do not match.");
    return res.redirect("/signup");
  } else if (!schema.validate(req.body.password)) {
    // password do not match requirements
    req.flash("signupErr", "Password must be at least 6 characters with at least 1 UPPER case, 1 lower case and 1 numeric digit.");
    return res.redirect("/signup");
  } else {
    User.findOne({
      username: req.body.username
    }, (err, foundUser) => {
      if (err) {
        console.log(err);
        res.render("failure");
      } else {
        if (foundUser) {
          req.flash("signupErr", "Email has already been registered.");
          return res.redirect("/signup");
        } else {
          User.register({
              displayName: req.body.displayName,
              username: req.body.username
            },
            req.body.password,
            (err, result) => {
              if (err) {
                console.log(err);
                res.render("failure");
              } else {
                passport.authenticate("local")(req, res, () => {
                  res.redirect("/dashboard");
                });
              }
            }
          );
        }
      }
    });
  }
});

router.post("/login", (req, res, next) => {
  let loginErrors = [];

  if (!req.body.username || !req.body.password) {
    loginErrors.push({
      msg: "Please fill in all fields."
    });
  }

  User.findOne({
    username: req.body.username
  }, (invalid, foundUser) => {
    if (invalid) {
      console.log(invalid);
    } else {
      if (!foundUser) {
        loginErrors.push({
          msg: "Email has not been registered."
        });
      } else {
        loginErrors.push({
          msg: "Invalid Password. Try Again."
        });
      }
    }
  });

  passport.authenticate("local", function(err, user, info) {
    if (err) {
      return next(err);
    }
    if (!user) {
      return res.render("login", {
        loginErrors: loginErrors
      });
    }

    req.login(user, function(err) {
      if (err) {
        return next(err);
      }
      return res.redirect("/dashboard");
    });
  })(req, res, next);
});

router.post("/forgot-password", function(req, res, next) {

  async.waterfall([
    done => {
      crypto.randomBytes(20, (err, buf) => {
        if (err) {
          console.log(err);
          res.render("failure");
        } else {
          const token = buf.toString("hex");
          done(err, token);
        }
      });
    },
    (token, done) => {

      User.findOne({
        username: req.body.username
      }, (err, user) => {
        if (err) {
          console.log(err);
          res.render("failure");
        } else if (!user) {
          console.log('error', 'No account with that email address exists.');
          return res.render('forgot', {
            forgotErr: "Email has not been registered.",
            forgotSuccess: ""
          });
        } else {
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 1200000; // 20min

          user.save((err) => {
            if (err) {
              console.log(err);
              res.render("failure");
            }
            done(err, token, user);
          });
        }
      });
    },
    (token, user, done) => {
      let transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'punkt.orbital@gmail.com',
          pass: process.env.GMAILPW
        }
      });
      const mailOptions = {
        from: 'punkt.orbital@gmail.com',
        to: user.username,
        subject: 'Punkt Password Reset',
        text: "Dear " + user.displayName + ", \n\n" +
        'You are receiving this because you have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/reset/' + token + '\n\n' +
          'If you did not request for password reset, please ignore this email and your password will remain unchanged.\n\n' +
          "Punkt Developer Team"
      };
      transporter.sendMail(mailOptions, function(err) {
        res.render("forgot", {
          forgotErr: "",
          forgotSuccess: "Please check your email (including spam mail) at " + user.username + " for further instructions."
        });
        done(err, "done");
      });
    }
  ], (err) => {
    if (err) {
      console.log(err);
      return next(err);
    }
    res.redirect("/forgot-password");
  });
});

router.get('/reset/:token', function(req, res) {
  User.findOne({
    resetPasswordToken: req.params.token,
    resetPasswordExpires: {
      $gt: Date.now()
    }
  }, function(err, user) {
    if (!user) {
      return res.render("forgot", {
        forgotErr: "Password reset token is invalid or has expired.",
        forgotSuccess: ""
      });
    } else {
      res.render("reset", {
        token: req.params.token,
      });
    }
  });
});

router.post("/reset/:token", (req, res) => {
  const resetErr = [];

  async.waterfall([
    (done) => {
      User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: {
          $gt: Date.now()
        }
      }, (err, user) => {
        if (err) {
          console.log(err);
          res.render("failure");
        } else {
          if (!user) {
            return res.render("forgot", {
              forgotErr: "Password reset token is invalid or has expired.",
              forgotSuccess: ""
            });
          } else {
            if (req.body.password !== req.body.password2) {
              req.flash("resetErr", "Passwords do not match.");
              return res.redirect("back");
            } else if (!schema.validate(req.body.password)) {
              // password do not match requirements
              req.flash("resetErr", "Password must be at least 6 characters with at least 1 UPPER case, 1 lower case and 1 numeric digit.");
              return res.redirect("back");
            } else {
              user.setPassword(req.body.password, (err) => {
                if (err) {
                  console.log(err);
                  res.render("failure");
                } else {
                  user.resetPasswordToken = undefined;
                  user.resetPasswordExpires = undefined;

                  user.save(function(err) {
                    req.login(user, function(err) {
                      done(err, user);
                    });
                  });
                }
              });
            }
          }
        }
      });
    },
    (user, done) => {
      let transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "punkt.orbital@gmail.com",
          pass: process.env.GMAILPW
        }
      });

      const mailOptions = {
        to: user.username,
        from: "punkt.orbital@gmail.com",
        subject: "Your password has been changed",
        text: "Dear " + user.displayName + ",\n\n" +
          "This is a confirmation that the password for your account " + user.username + " has just been changed.\n\n" +
          "Punkt Developer Team"
      };
      transporter.sendMail(mailOptions, function(err) {
        if (err) {
          console.log(err);
          res.render("failure");
        } else {
          req.flash("resetSuccess", "Yay! Your password has been changed successfully.");
          done(err);
        }
      });
    }
  ], (err) => {
    if (err) {
      console.log(err);
      res.render("failure");
    } else {
      res.redirect("/login");
    }
  });
});

module.exports = router;

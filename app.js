// jshint esversion: 8
require('dotenv').config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const $ = require('jquery');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const User = require("./models/user");
const flash = require("express-flash");
const app = express();


app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(express.static("public"));
app.use(flash());

app.use(session({
  secret: "Orbital 2021 Punkt.",
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 60000
  }
  // cookie: { secure: true }
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect('mongodb+srv://Punkt:Orbital2021@cluster1.2saoh.mongodb.net/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

mongoose.set("useCreateIndex", true);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// app.use("/", require("./routes/user"));
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/dashboard", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("dashboard");
  } else {
    res.redirect("/login");
  }
});

let PORT = process.env.PORT;
if (PORT == null || port == "") {
  PORT = 3000;
}

app.listen(PORT, () => {
  console.log("Server started successfully.");
});
// const PORT = process.env.PORT || 3000;
//
// app.listen(PORT, console.log(`Server running on ${PORT}`));

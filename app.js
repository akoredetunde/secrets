//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const app = express();

app.set("view engine", "ejs");
app.use(bodyparser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());


// /setting up Database using mongoose//////////////
mongoose.connect("mongodb://0.0.0.0:27017/userDB");
const userScherma = new mongoose.Schema({
  username: String,
  password: String,
  secret: [String]
});
const options = {
  limitAttempts: true,
  maxAttempts: 4,
  unlockInterval: 3600000,
  errorMessages:{
    TooManyAttemptsError: "Too many attempts, try again after an hour."
  }
};
userScherma.plugin(passportLocalMongoose, options);
userScherma.plugin(findOrCreate);

const userModel = mongoose.model("User", userScherma);

passport.use(userModel.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  userModel.findById(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
  },
  function(accessToken, refreshToken, profile, cb) {
    userModel.findOrCreate({ username: profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secret",
    profileFields: ["id", "email", "name"]
  },
  function(accessToken, refreshToken, profile, cb) {
    userModel.findOrCreate({username: profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));


// //////configuration of request made to home route/////////////////
app.route("/")
.get(function (req, res) {
  res.render("home");
});

app.route("/auth/google")
.get(passport.authenticate("google", {scope: ["email", "profile"] }));

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.redirect("/secrets");
});

app.route("/auth/facebook")
.get(passport.authenticate("facebook", {scope: "email"}));

app.get("/auth/facebook/secret",
  passport.authenticate("facebook", { failureRedirect: "/login"}),
  function(req, res) {
    res.redirect("/secrets");
  });

// //////configuration of request made to register route/////////////////
app.route("/register")
.get(function (req, res) {
  res.render("register", {
    errMsg: "",
    email: "",
    password: ""
  });
})

.post(function (req, res) {
  userModel.register({username: req.body.username}, req.body.password, function (err, user) {
    if(err){
      res.render("register", {
        errMsg: err.message,
        email: "",
        password: ""
      });
    }else{
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    };
  });
});


// //////configuration of request made to login route/////////////////
app.route("/login")

.get(function (req, res) {

  if(req.session.messages=== undefined){
    res.render("login", {
      errMsg: "",
      email: "",
      password: ""
    });
  }else{
    var message = req.session.messages;
    const err = message[message.length - 1];
    message=[];
    res.render("login", {
      errMsg: err,
      email: "",
      password: ""
    });
  };


})

.post(passport.authenticate("local",{ failureRedirect: "/login", failureMessage: true}), function (req, res) {
  res.redirect("/secrets");
});

app.route("/logout")
.get(function (req, res) {
  req.logout(function (err) {
    if(err){
      console.log(err);
    }else{
      res.redirect("/")
    };
  });
});

app.route("/secrets")
.get(function (req, res) {
  if(req.isAuthenticated()){
    userModel.findOne({username: req.user.username}, function (err, foundUser) {
      if(err){
        console.log(err);
      }else{
        res.render("secrets", {
          secrets: foundUser.secret
        });
      };
    });
  }else{
    res.redirect("/login");
  };
});

app.route("/submit")
.get(function (req, res) {
  if(req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  };
})
.post(function (req, res) {
  const secret = req.body.secret;
  userModel.updateOne({username: req.user.username},{$push: {secret: secret}}, function (err) {
    if(err){
      console.log(err);
    }else{
      res.redirect("/secrets");
    };
  });
});



const port = process.env.PORT||3000;
app.listen(port, function () {
  console.log("App is running on " + port);
});

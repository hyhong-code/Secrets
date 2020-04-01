require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook");
const findOrCreate = require("mongoose-findorcreate");

const app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Initialize session with options
app.use(
    session({
        secret: process.env.SECRET,
        resave: false,
        saveUninitialized: false
    })
);
// Initialize passport
app.use(passport.initialize());
// Setup session with passport
app.use(passport.session());

mongoose.connect(
    "mongodb+srv://admin-denny:" +
        process.env.MONGO_KEY +
        "@cluster0-6oano.mongodb.net/secretDB",
    {
        useNewUrlParser: true,
        useUnifiedTopology: true
    }
);
const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secrets: []
});

// Setup passportLocalMongoose
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

// Config sessions to support login sessions
passport.use(User.createStrategy()); // For local Strategy
passport.serializeUser(function(user, done) {
    done(null, user.id);
});
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

// Configure Google Strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GG_ID,
            clientSecret: process.env.GG_SECRET,
            callbackURL:
                "https://pumpkin-pie-62020.herokuapp.com/auth/google/secrets"
        },
        function(accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ googleId: profile.id }, function(err, user) {
                return cb(err, user);
            });
        }
    )
);

// Configure Facebook Strategy
passport.use(
    new FacebookStrategy(
        {
            clientID: process.env.FB_ID,
            clientSecret: process.env.FB_SECRET,
            callbackURL:
                "https://pumpkin-pie-62020.herokuapp.com/auth/facebook/secrets"
        },
        function(accessToken, refreshToken, profile, cb) {
            User.findOrCreate({ facebookId: profile.id }, function(err, user) {
                return cb(err, user);
            });
        }
    )
);

// Home route get request
app.get("/", function(req, res) {
    res.render("home");
});

// Secret route get request
app.get("/secrets", function(req, res) {
    // Find all secrets in DB in order to display them
    User.find({ secrets: {$exists: true, $ne: []} }, function(err, foundUsers) {
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                console.log(foundUsers);
                res.render("secrets", { usersWithSecrets: foundUsers });
            }
        }
    });
});

// Submit route get request
app.get("/submit", function(req, res) {
    // passport method
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    const submittedSecret = req.body.secret;
    // Passport saves req.user
    User.findById(req.user._id, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                foundUser.secrets.push(submittedSecret);
            }
            foundUser.save();
            res.redirect("/secrets");
        }
    });
});

// app.post("/submit", function(req, res) {
//     const submittedSecret = req.body.secret;
//     // Passport saves req.user
//     User.findById(req.user._id, function(err, foundUser) {
//         if (err) {
//             console.log(err);
//         } else {
//             if (foundUser) {
//                 foundUser.secret = submittedSecret;
//             }
//             foundUser.save();
//             res.redirect("/secrets");
//         }
//     });
// });

// Register route get request
app.get("/register", function(req, res) {
    res.render("register");
});

// Handle Register route post request
app.post("/register", function(req, res) {
    User.register({ username: req.body.username }, req.body.password, function(
        err,
        user
    ) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function(err) {
                if (err) {
                    console.log(err);
                } else {
                    res.redirect("/secrets");
                }
            });
        }
    });
});

// Login route get request
app.get("/login", function(req, res) {
    res.render("login");
});

// Handle Login route post request
app.post("/login", function(req, res) {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    // passport method
    req.login(user, function(err) {
        if (err) {
            console.log(err);
            res.redirect("/login");
        } else {
            passport.authenticate("local")(req, res, function(err) {
                if (err) {
                    console.log(err);
                    res.redirect("/login");
                } else {
                    res.redirect("/secrets");
                }
            });
        }
    });
});

// Google Authenticate Requests route
app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);
// Google callbackURL route
app.get(
    "/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect /secrets.
        res.redirect("/secrets");
    }
);

// Facebook Authenticate Requests route
app.get("/auth/facebook", passport.authenticate("facebook"));
// Google callbackURL route
app.get(
    "/auth/facebook/secrets",
    passport.authenticate("facebook", { failureRedirect: "/login" }),
    function(req, res) {
        // Successful authentication, redirect /secrets.
        res.redirect("/secrets");
    }
);

// Logout route get request
app.get("/logout", function(req, res) {
    req.logout(); // passport method
    res.redirect("/");
});

app.listen(process.env.PORT || 3000, function() {
    console.log("Server is running on port 3000...");
});

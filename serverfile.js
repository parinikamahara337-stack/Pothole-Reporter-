var express = require("express");
var mongoose = require("mongoose");
var session = require("express-session");
var bcrypt = require("bcryptjs");
var path = require("path");

var app = express();
var PORT = 3000;

mongoose.connect("mongodb://localhost:27017/potholeDB")
    .then(function () {
        console.log("Connected to MongoDB");
    })
    .catch(function (err) {
        console.log("MongoDB connection failed: " + err.message);
    });

var userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

var reportSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    location: { type: String, required: true },
    roadType: String,
    severity: String,
    description: { type: String, required: true },
    photo: String,
    status: { type: String, default: "Reported" },
    date: { type: Date, default: Date.now }
});

var User = mongoose.model("User", userSchema);
var Report = mongoose.model("Report", reportSchema);

app.use(express.json({ limit: "5mb" }));
app.use(session({
    secret: "civicpulse-secret-key",
    resave: false,
    saveUninitialized: false
}));

function checkLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: "Please log in first" });
    }
    next();
}

function needLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login.html");
    }
    next();
}

app.get("/", needLogin, function (req, res) {
    res.sendFile(path.join(__dirname, "files", "index.html"));
});

app.get("/login.html", function (req, res) {
    if (req.session.userId) {
        return res.redirect("/index.html");
    }
    res.sendFile(path.join(__dirname, "files", "login.html"));
});

["index.html", "report.html", "myreports.html"].forEach(function (page) {
    app.get("/" + page, needLogin, function (req, res) {
        res.sendFile(path.join(__dirname, "files", page));
    });
});

app.use(express.static(path.join(__dirname, "files"), { index: false }));

app.post("/api/signup", function (req, res) {
    var name = (req.body.name || "").trim();
    var email = (req.body.email || "").trim().toLowerCase();
    var password = req.body.password || "";

    if (name === "" || email === "" || password === "") {
        return res.status(400).json({ error: "Please fill in all the fields." });
    }
    if (password.length < 6) {
        return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    User.findOne({ email: email })
        .then(function (existing) {
            if (existing) {
                return res.status(400).json({ error: "This email is already registered. Please sign in." });
            }
            var hashed = bcrypt.hashSync(password, 10);
            var newUser = new User({ name: name, email: email, password: hashed });
            return newUser.save().then(function (saved) {
                req.session.userId = saved._id;
                req.session.name = saved.name;
                res.json({ name: saved.name });
            });
        })
        .catch(function (err) {
            res.status(500).json({ error: "Could not sign up. Try again." });
        });
});

app.post("/api/login", function (req, res) {
    var email = (req.body.email || "").trim().toLowerCase();
    var password = req.body.password || "";

    User.findOne({ email: email })
        .then(function (user) {
            if (!user || !bcrypt.compareSync(password, user.password)) {
                return res.status(400).json({ error: "Wrong email or password." });
            }
            req.session.userId = user._id;
            req.session.name = user.name;
            res.json({ name: user.name });
        })
        .catch(function (err) {
            res.status(500).json({ error: "Could not log in. Try again." });
        });
});

app.post("/api/logout", function (req, res) {
    req.session.destroy(function () {
        res.json({ message: "Logged out" });
    });
});

app.get("/api/me", function (req, res) {
    if (req.session.userId) {
        res.json({ loggedIn: true, name: req.session.name });
    } else {
        res.json({ loggedIn: false });
    }
});

app.get("/api/count", function (req, res) {
    Report.countDocuments()
        .then(function (count) {
            res.json({ count: count });
        })
        .catch(function (err) {
            res.json({ count: 0 });
        });
});

app.get("/api/reports", checkLogin, function (req, res) {
    Report.find({ user: req.session.userId }).sort({ date: -1 })
        .then(function (reports) {
            res.json(reports);
        })
        .catch(function (err) {
            res.status(500).json({ error: "Could not get reports" });
        });
});

app.post("/api/reports", checkLogin, function (req, res) {
    var newReport = new Report({
        user: req.session.userId,
        location: req.body.location,
        roadType: req.body.roadType,
        severity: req.body.severity,
        description: req.body.description,
        photo: req.body.photo
    });

    newReport.save()
        .then(function (saved) {
            res.json(saved);
        })
        .catch(function (err) {
            res.status(400).json({ error: "Could not save report. Location and description are required." });
        });
});

app.put("/api/reports/:id", checkLogin, function (req, res) {
    Report.findOneAndUpdate(
        { _id: req.params.id, user: req.session.userId },
        { status: "Fixed" },
        { new: true }
    )
        .then(function (updated) {
            res.json(updated);
        })
        .catch(function (err) {
            res.status(500).json({ error: "Could not update report" });
        });
});

app.delete("/api/reports/:id", checkLogin, function (req, res) {
    Report.findOneAndDelete({ _id: req.params.id, user: req.session.userId })
        .then(function () {
            res.json({ message: "Deleted" });
        })
        .catch(function (err) {
            res.status(500).json({ error: "Could not delete report" });
        });
});

app.listen(PORT, function () {
    console.log("Server running at http://localhost:" + PORT);
});
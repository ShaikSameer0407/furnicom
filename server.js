const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const ejs = require("ejs");
const bcrypt = require("bcrypt");
const path = require('path');

const admin = require("firebase-admin");
const account = require("./key.json");
app.use(express.static(path.join(__dirname, 'public')));

admin.initializeApp({
    credential: admin.credential.cert(account),
});
const db = admin.firestore();

app.use(bodyParser.urlencoded({ extended: true }));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));  // Ensure correct view path

app.get("/", (req, res) => {
    res.render("home");
});
app.get("/home", (req, res) => {
    res.render("home");
});

app.get("/signup", (req, res) => {
    res.render("signup", { error: "" });
});

app.post("/signup", async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    console.log(username, email, password);
    try {
        const userrecord = await admin.auth().createUser({
            username: username,
            email: email,
        });
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.collection("users").doc(userrecord.uid).set({
            name: username,
            email: email,
            password: hashedPassword,
        });
        console.log("Successfully created", userrecord.uid);
        res.render("home");
    } catch (error) {
        const errormessage = error.errorInfo.message;
        console.error("Error creating new user:", error);
        res.render("signup", { error: errormessage });
    }
});

app.get("/signin", (req, res) => {
    res.render("signin", { error: "" });
});

app.post("/signin", async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    console.log(email, password);
    try {
        const userRecord = await admin.auth().getUserByEmail(email);
        console.log("Successfully fetched:", userRecord.uid);
        const userdetails = await db.collection("users").doc(userRecord.uid).get();

        if (!userdetails.exists) {
            console.log("User not found in Firestore.");
            return res.render("signin", { error: "User not found in database" });
        }

        const userData = userdetails.data();
        const hashedPassword = userData.password;
        const result = await bcrypt.compare(password, hashedPassword);

        if (result === true) {
            res.redirect("/home");
        } else {
            res.render("signin", { error: "Password not matched" });
        }
    } catch (error) {
        if (error.code === 'auth/user-not-found') {
            res.render("signin", { error: "No user found with this email" });
        } else {
            const errormessage = error?.errorInfo?.message || "An unknown error occurred";
            console.error("Error is:", error);
            res.render("signin", { error: errormessage });
        }
    }
});

app.listen(4000, () => {
    console.log("Server started at: 4000");
});

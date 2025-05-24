const mongoose = require("mongoose");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const router = express.Router();
const usersSchema = require("../schema/usersSchema")
const User = new mongoose.model("User", usersSchema);

// sign up api
router.post("/signup", async (req, res) => {
    try {
        const { username, email, password } = req.body;
        // find user in db
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        const result = await newUser.save();
        // console.log(result);
        return res.status(200).json({ message: "User created successfully" });
    } catch (error) {
        return res.status(500).json({ message: error.message });
    }
});

// sign in or login api
router.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "user not found !" });
        }
        const matchPassword = await bcrypt.compare(password, user.password);
        if (!matchPassword) {
            return res.status(400).json({ message: "password done not match " });
        };

        // generate token 
        const token = jwt.sign(
            {
                user_id: user._id,
                username: user.username,
                email: user.email
            },
            process.env.JWT_SECRET, {
            expiresIn: "1d"
        }
        );

        res.cookie("token", token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });

        res.json({
            message: "login success",
            user: {
                _id: user._id,
                username: user.username,
                email: user.email
            }
        })
        

    } catch (error) {
        return res.status(500).json({ message: "something is wrong ", error })
    }
});


router.post("/logout", async (req, res) => {
    res.clearCookie("token");
    res.json({ message: "logout success" });
})



module.exports = router;
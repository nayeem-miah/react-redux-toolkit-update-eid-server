const mongoose = require("mongoose");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const router = express.Router();
const usersSchema = require("../schema/usersSchema")
const User = new mongoose.model("User", usersSchema);

// Signup API
router.post("/signup", async (req, res) => {
    try {
        let { username, email, password } = req.body;

        // Basic input validation
        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields are required" });
        }

        username = username.trim();
        email = email.trim().toLowerCase();
        password = password.trim();

        if (password.length < 6) {
            return res.status(400).json({ message: "Password must be at least 6 characters long" });
        }

        //  Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: "Email already exists" }); // 409 Conflict
        }

        //  Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        //  Create new user and save to DB
        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        const savedUser = await newUser.save();

        //  Respond with success
        return res.status(201).json({
            message: "User created successfully",
            userId: savedUser._id,
            result: savedUser
        });

    } catch (error) {
        console.error("Signup error:", error.message);
        return res.status(500).json({ message: "Server error. Please try again later." });
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
                email: user.email,
                createdAt : user.createdAt
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
                email: user.email,
                createdAt: user.createdAt
            }
        })
        

    } catch (error) {
        return res.status(500).json({ message: "something is wrong ", error })
    }
});

// logout or clear cookie
router.post("/logout", async (req, res) => {
    res.clearCookie("token");
    res.json({ message: "logout success" });
})

// Protected route to check authentication

router.get("/protected", async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: "Unauthorized" });
    };

    // verify token 
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: "Invalid token" });
        };
        res.json({
            message: "user is authenticated",
            user: {
                user_id: decoded._id,
                username: decoded.username,
                email: decoded.email
            }
        })
    })
});




module.exports = router;
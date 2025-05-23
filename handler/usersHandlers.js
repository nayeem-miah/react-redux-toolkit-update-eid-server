const mongoose = require("mongoose");
const express = require("express");
const bcrypt = require("bcryptjs");
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




module.exports = router;
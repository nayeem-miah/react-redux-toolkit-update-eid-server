const mongoose = require("mongoose");

const usersSchema = new mongoose.Schema({
    username: {
        type: String,
        required: [true, "Username is required"],
        trim: true
    },
    email: {
        type: String,
        required: [true, "Email is required"],
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: [true, "Password is required"],
        minlength: [6, "Password must be at least 6 characters"],
        maxlength: [100, "Password must not exceed 100 characters"]
    }
}, {
    timestamps: true // Optional: adds createdAt and updatedAt fields
});

// Export the model
module.exports = usersSchema;

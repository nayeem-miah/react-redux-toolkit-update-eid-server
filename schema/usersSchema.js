const mongoose = require("mongoose");

const usersSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String || Number,
        required: true,
        max: 10,
        min: 6
    }
});

module.exports = usersSchema;
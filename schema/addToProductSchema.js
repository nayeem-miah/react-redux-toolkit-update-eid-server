const mongoose = require("mongoose");

const addToCartSchema = new mongoose.Schema({
    product_img: {
        type: String,
        required: true
    },
    name: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    category: {
        type: String,
        required: true
    },
    brand: {
        type: String,
        required: true
    },
    size: {
        type: String,
        required: false
    },
    color: {
        type: String,
        required: false
    },
    material: {
        type: String,
        required: false
    },
    availability: {
        type: String,
        required: true
    },
    rating: {
        type: Number,
        required: false
    },
    email: {
        type: String,
        required: true
    },
    addedAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model("addToCart", addToCartSchema);

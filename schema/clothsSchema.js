const mongoose = require("mongoose");

const clothsSchema = new mongoose.Schema({
    product_img: {
        type: String,
        required: true
    },
    name: {
        type: String,
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
    price: {
        type: Number,
        required: true
    },
    size: {
        type: String, 
        required: true
    },
    color: {
        type: String,
        required: true
    },
    material: {
        type: String,
        required: true
    },
    rating: {
        type: Number,
        default: 0
    },
    availability: {
        type: String,
        enum: ["In Stock", "Out of Stock"],
        default: "In Stock"
    }
}, {
    timestamps: true
});

module.exports = mongoose.model("Cloth", clothsSchema);

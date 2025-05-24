const express = require("express");
const router = express.Router();
const AddToCart = require("../schema/addToProductSchema");

// added post product
router.post("/add-product", async (req, res) => {
    try {
        const newAddedData = new AddToCart(req.body);
        const result = await newAddedData.save();
        res.status(200).json({ message: "add to cart success", data: result });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "something is wrong ", error: error })
    }
});

// get all product email ways
router.get("/get-product/:email", async (req, res) => {
    try {
        const email = req.params.email;
        const result = await AddToCart.find({ email })
        res.status(200).json({ data: result })
    } catch (error) {
        return res.status(500).json({ message: "something is wrong ", error })
    }
});

// delete added product
router.delete("/delete-product/:id", async (req, res) => {
})

module.exports = router;
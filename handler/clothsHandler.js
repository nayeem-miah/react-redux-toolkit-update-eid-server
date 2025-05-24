const express = require("express");
const router = express.Router();
const Cloths = require('../schema/clothsSchema');

router.get("/all-products", async (req, res) => {

    try {
        const search = req.query.search || "";
        const query = search ? {
            $or: [
                { name: { $regex: search, $options: "i" } },
                { brand: { $regex: search, $options: "i" } },
                { category: { $regex: search, $options: "i" } },
            ],
            
        } : {};

        const result = await Cloths.find(query);
        res.status(200).json({ data: result })
    } catch (error) {
        return res.status(500).json({ message: "somethings is wrong", error })
    };
});
router.post("/add-product", async (req, res) => {
     
 })
router.get("/product/:id", async (req, res) => {
     
 })
router.put("/updated-product/:id", async (req, res) => {
     
 })
router.delete("/delete-product/:id", async (req, res) => {
     
})
 
module.exports = router;


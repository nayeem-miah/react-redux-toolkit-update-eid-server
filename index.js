const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const usersHandler = require("./handler/usersHandlers");
const clothsHandler = require("./handler/clothsHandler");
const addToCartHandler = require("./handler/addToProductHandler");

const app = express();
const port = process.env.PORT || 5000;
require("dotenv").config();

// Middleware
app.use(cors({
  origin: ["http://localhost:5173","https://eid-special-react-update.netlify.app"],
  credentials: true, 
}));
app.use(express.json());
app.use(cookieParser());




// MONGODB
 // const uri =`mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.bomlehy.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const uri = 'mongodb://localhost:27017/eidSpecial'
mongoose.connect(uri)
  .then(() => console.log("db connect"))
  .catch((err) => console.log(err));


// application routes
app.use('/users', usersHandler);
app.use("/cloths", clothsHandler);
app.use("/add-cart", addToCartHandler);


 
  
  //     // add to cart product
  //     app.post('/carts', async (req, res) => {
  //       const cart = req.body;
  //       // console.log(cart);
  //       const result = await cartCollection.insertOne(cart);
  //       res.send(result);
  //     })
 
      
  //     // get single added product
  //     app.get('/cart/:email', async (req, res) => {
  //       const email = req.params.email;
  //       const query = { email: email };
  //       const result = await cartCollection.find(query).toArray();
  //       // console.log(result);
  //       res.send(result);
  //     })

  //     // delete added product
  //     app.delete('/cart-delete/:id', async (req, res) => {
  //       const id = req.params.id;
  //       const query = { _id: new ObjectId(id) };
  //       const result = await cartCollection.deleteOne(query);
  //       // console.log(result);
  //       res.send(result);
  //     })



// default error handler
const errorHandler = (err, req, res, next) => {
  if (res.headersSent) {
    return next(err)
  }
  res.status(500).json({ message: err.message })
};
app.use(errorHandler);

app.get("/", (req, res) => {
    res.send("Hello World! from eid-special");
});

app.listen(port, () => {
    console.log(`Example app listening on port http://localhost:${port}`);
});


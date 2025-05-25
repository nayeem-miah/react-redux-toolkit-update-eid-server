const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const mongoose = require("mongoose");
const usersHandler = require("./handler/usersHandlers");
const clothsHandler = require("./handler/clothsHandler");
const addToCartHandler = require("./handler/addToProductHandler");

// express with init
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


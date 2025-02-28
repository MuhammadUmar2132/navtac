const express = require('express');
const mongoose = require('mongoose');
const {PORT} = require('./config/index');
const dbConnect = require("./database/index");
const router = require("./routes/index");
const errorHandler = require("./middlewares/errorHandler");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());
const cors = require("cors");

app.use(
    cors({
      origin: function (origin, callback) {
        return callback(null, true);
      },
      optionsSuccessStatus: 200,
      credentials: true,
    })
  );
  
app.use(express.json({ limit: "50mb" }));
app.use(router);

dbConnect();

app.use("/storage", express.static("storage"));
app.use(errorHandler);

app.listen(PORT, ()=>{
    console.log(`Backend is running on port: ${PORT}`)
});


//app.use('/register',router);n
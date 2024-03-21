const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const winston = require("winston");
const morgan = require("morgan");
const bodyParser = require("body-parser");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

require("dotenv").config();

const { User } = require("./models/user");

const app = express();
const port = 3000;

app.use(morgan("tiny"));

const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  defaultMeta: { service: "user-service" },
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// Custom logger stream for Winston and Morgan integration
logger.stream = {
  write: function (message, encoding) {
    logger.info(message.trim());
  },
};

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// mongoose.connect(process.env.MONGODB_URL);
// mongoose.connection.on("connected", () => console.log("mongodb connected"));
// mongoose.connection.on("error", (err) => {
//   console.log(err);
// });

app.get("/", (req, res) => {
  res.send("Hello World!");
});



app.get("/auth/setup-totp", async (req, res) => {
  try {
   

    // Generate secret key
    const secret = speakeasy.generateSecret({ length: 20 });

    // Generate QR code URL
    const qrCodeUrl = speakeasy.otpauthURL({
      secret: secret.ascii,
      label: "MyApp",
      issuer: "Google",
    });

    // await User.findByIdAndUpdate(
    //   { _id: userId },
    //   { secret: secret.base32, is2FAEnabled: true }
    // );

    // Convert QR code URL to QR code image
    const imageUrl = await QRCode.toDataURL(qrCodeUrl);

    res.send(`<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Centered Square Image</title>
    <style>
      body, html {
        height: 100%;
        margin: 0;
        display: flex;
        justify-content: center;
        align-items: center;
      }
      #container {
        width: 300px; /* Adjust the width of the container as needed */
        height: 300px; /* Set the height equal to width to make it a square */
        border: 1px solid black; /* Optional border */
        display: flex;
        justify-content: center;
        align-items: center;
      }
      #image {
        max-width: 100%; /* Make sure the image does not exceed the container */
        max-height: 100%; /* Make sure the image does not exceed the container */
      }
    </style>
    </head>
    <body>
      <div id="container">
        <img id="image" src=${imageUrl} alt="Square Image">
      </div>
      <div>${secret.base32}</div>
    </body>
    </html>
    `);
  } catch (error) {
    console.error(error);
  }
});

app.post("/auth/verify-totp", async (req, res) => {
  try {
    const { secretKey, code } = req.body;

    // const user = await User.findById({ _id: userId });

    // if (!user) {
    //   return res.status(404).json({ message: "User not found" });
    // }

    const verified = speakeasy.totp.verify({
      secret: secretKey,
      encoding: "base32",
      token: code,
      window: 1, // Allow 1-step tolerance
    });

    if (!verified) {
      return res.status(400).json({ message: "Invalid TOTP token" });
    }


    // Generate access token
    const accessToken = jwt.sign(
      { userId: secretKey },
      process.env.JWT_SECRET_KEY,
      {
        expiresIn: "15m",
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { userId: secretKey },
      process.env.JWT_SECRET_KEY,
      {
        expiresIn: "7d",
      }
    );

    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error(error);
  }
});

// Error handling
app.use((err, req, res, next) => {
  logger.error(
    `${err.status || 500} - ${err.message} - ${req.originalUrl} - ${
      req.method
    } - ${req.ip}`
  );
  res.status(err.status || 500).send("Internal Server Error");
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

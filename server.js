import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cors from "cors";

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

mongoose
  .connect(process.env.SECRET_DB_CONNECTION)
  .then((res) => console.log("db connect"))
  .catch((res) => console.log("connection err"));

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  refreshToken: String,
});

const User = mongoose.model("User", userSchema);

app.post("/api/user/signup", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPass = await bcrypt.hash(password, 10);

    const userExists = await User.findOne({ username });
    if (userExists) {
      return res.status(301).json({
        data: [],
        message: "user exists",
      });
    }

    const newUser = new User({ username, password: hashedPass });
    await newUser.save();

    return res.status(201).json({
      data: newUser,
      message: "new user created",
    });
  } catch (error) {
    return res.status(401).json({
      data: [],
      message: "cant user signup",
    });
  }
});

app.post("/api/user/login", async (req, res) => {
  try {
    const { username, password } = await req.body;

    const user = await User.findOne({ username });
    console.log(user);
    if (!user) {
      return res.status(401).json({
        data: [],
        message: "User not found",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    console.log("isMatch", isMatch);
    if (!isMatch) {
      return res.status(401).json({ message: "Wrong password" });
    }

    const payload = {
      id: user._id,
      username: user.username,
    };

    // accessToken
    const accessToken = jwt.sign(payload, process.env.SECRET_JWT_ACCESS, {
      expiresIn: "10s",
    });

    // refreshToken
    const refreshToken = jwt.sign(payload, process.env.SECRET_JWT_REFRESH, {
      expiresIn: "7d",
    });
    user.refreshToken = refreshToken;
    await user.save();

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    console.log(error);
    return res.status(401).json({
      data: [],
      message: "cant user login",
    });
  }
});

app.post("/api/token", async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) return res.status(401).json({ message: "No token" });

  // پیدا کردن یوزر
  const user = await User.findOne({ refreshToken });
  if (!user) return res.status(403).json({ message: "Invalid refresh token" });

  try {
    const payload = jwt.verify(refreshToken, process.env.SECRET_JWT_REFRESH);

    // تولید Access Token جدید
    const accessToken = jwt.sign(
      { id: user._id, username: user.username },
      process.env.SECRET_JWT_ACCESS,
      { expiresIn: "15m" }
    );

    res.json({ accessToken });
  } catch (err) {
    res.status(403).json({ message: "Refresh token expired" });
  }
});



const authenticationJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({
      message: "token expired",
    });
  }
  const token = authHeader.split(" ")[1];
  try {
    // verify toke
    const decode = jwt.verify(token, process.env.SECRET_JWT_ACCESS);
    req.user = decode;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

app.get("/api/user/profile", authenticationJWT, (req, res) => {
  const user = req.user;
  console.log(user);
  res.json({
    data: user,
    message: "ok profile",
  });
});

app.listen(5000, () => console.log("connected"));

import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import jwt, { decode } from "jsonwebtoken";

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = "1763357486522";

mongoose
  .connect("mongodb://localhost:27017/JWT")
  .then((res) => console.log("connected"))
  .catch((res) => console.log(res));

const userSchema = new mongoose.Schema({
  username: { type: String },
  email: String,
  role: String,
  password: String,
});

const User = mongoose.model("User", userSchema);

app.post("/api/user/signup", async (req, res) => {
  try {
    const { username, role, password } = req.body;

    const newUser = new User({ username, role, password });
    await newUser.save();

    res.status(200).json({
      message: "profile accesed",
      user: newUser,
    });
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "invalid user", err: { error } });
  }
});

app.post("/api/user/login", async (req, res) => {
  const { username, password } = req.body;

  // find user
  const users = await User.find();
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "invalid credentials" });
  }

  const payload = {
    id: user.id,
    username: user.username,
    role: user.role,
  };

  // sign token
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
  res.json({ message: "login successful", token });
});

const authenticationJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Token missing" });
  }
  const token = authHeader.split(" ")[1];

  try {
    // verify token
    const decoded = jwt.verify(token, JWT_SECRET);

    // attach user to request
    req.user = decoded;

    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

// Protected route
app.get("/api/user/profile", authenticationJWT, async (req, res) => {

  const user = req.user._id
  console.log(user)
  
  res.status(200).json({
    message: "profile accesed",
    user: req.user,
  });
});

// Role-based route
app.get("/api/user/admin", authenticationJWT, async (req, res) => {
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Access denied: admin role required" });
  }
  res.json({ message: "Admin panel accessed" });
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});

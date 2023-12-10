const User = require("../Models/UserModel");
const { createSecretToken } = require("../util/SecretToken");
const bcrypt = require("bcryptjs");

module.exports.Signup = async (req, res, next) => {
  try {
    const { email, password, username, createdAt } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ message: "User already exists" });
    }
    const user = await User.create({ email, password, username, createdAt });
    const token = createSecretToken(user._id);     // Generate a secret token for this user
    //debugger
    res.cookie("token", token, {     // Set the token as a cookie in the response
      withCredentials: true,
      httpOnly: false,
    });
    res.status(201).json({ message: "User signed in successfully", success: true, user });
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }};

module.exports.Login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.json({ message: 'All fields are required' });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ message: 'Incorrect email' });
    }
    const auth = await bcrypt.compare(password, user.password); // Compare the provided password with the stored hashed password
    if (!auth) {
      return res.json({ message: 'Incorrect password' });
    }
    const token = createSecretToken(user._id);    // If the passwords match, generate a secret token for the user

    res.cookie("token", token, {     // Set the token as a cookie in the response
      withCredentials: true,
      httpOnly: false,
    });
    res.status(201).json({ message: "User logged in successfully", success: true });
    next();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};
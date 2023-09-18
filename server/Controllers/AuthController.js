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
    // Generate a secret token for this user
    const token = createSecretToken(user._id);
    // Set the token as a cookie in the response
    res.cookie("token", token, {
      withCredentials: true,
      httpOnly: false,
    });
    res.status(201).json({ message: "User signed in successfully", success: true, user });
    next();
  } catch (error) {
    console.error(error);
  }};

module.exports.Login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    // Check if both email and password are provided
    if (!email || !password) {
      return res.json({ message: 'All fields are required' });
    }

    // Find a user with the provided email
    const user = await User.findOne({ email });

    // If no user is found, send an error response
    if (!user) {
      return res.json({ message: 'Incorrect password or email' });
    }

    // Compare the provided password with the stored hashed password
    const auth = await bcrypt.compare(password, user.password);

    // If the passwords don't match, send an error response
    if (!auth) {
      return res.json({ message: 'Incorrect password or email' });
    }

    // If the passwords match, generate a secret token for the user
    const token = createSecretToken(user._id);

    // Set the token as a cookie in the response
    res.cookie("token", token, {
      withCredentials: true,
      httpOnly: false,
    });

    // Send a success response indicating that the user is logged in
    res.status(201).json({ message: "User logged in successfully", success: true });

    // Move on to the next middleware or route handler
    next();
  } catch (error) {
    // Handle any errors that may occur during this process
    console.error(error);
  }
};


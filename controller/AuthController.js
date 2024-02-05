// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
// const UserModel = require('../models/UserModel');
// const secretKey = 'your-secret-key'; // Replace with your actual secret key

// const register = async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     if (!username || !password) {
//       return res.status(400).json({ error: 'Username and password are required' });
//     }
//     const hashedPassword = await bcrypt.hash(password, 10);
//     const user = await UserModel.createUser(username, hashedPassword);
//     const token = jwt.sign({ id: user.id, username }, secretKey);
//     res.header('x-auth-token', token).json({ message: 'User registered successfully', token });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// const login = async (req, res) => {
//   try {
//     const { username, password } = req.body;
//     const user = await UserModel.getUserByUsername(username);
//     if (!user) {
//       return res.status(401).json({ error: 'Invalid username or password' });
//     }
//     const validPassword = await bcrypt.compare(password, user.hashed_password);
//     if (!validPassword) {
//       return res.status(401).json({ error: 'Invalid username or password' });
//     }
//     const token = jwt.sign({ id: user.id, username: user.username }, secretKey);
//     res.json({ token });
//   } catch (error) {
//     res.status(500).json({ error: error.message });
//   }
// };

// module.exports = { register, login };

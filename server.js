const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const socketIo = require('socket.io');
const http = require('http');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
  },
});

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
  email: String,
  username: String,
  phoneNumber: String,
  password: String,
  role: String,
  activeToken: String,
});

const User = mongoose.model('User', UserSchema);

app.use(express.json());
app.use(cors());

const activeUsers = new Map(); 

app.post('/auth/register', async (req, res) => {
  const { email, username, phoneNumber, password, role } = req.body;
  try {
    console.log(`Attempting to register user with email: ${email}`);
    const userExists = await User.findOne({ email });
    if (userExists) {
      console.log('Email already in use');
      return res.status(400).json({ message: 'Email already in use' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ email, username, phoneNumber, password: hashedPassword, role });
    await newUser.save();
    console.log('User registered successfully');
    res.json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    console.log(`User attempting login: ${email}`);
    const user = await User.findOne({ email });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log('Invalid email or password');
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    if (user.activeToken) {
      console.log(`Invalidating previous session for user: ${email}`);
      io.to(user._id.toString()).emit('logout', { message: 'You have been logged out due to a new login.' });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    user.activeToken = token;
    await user.save();

    console.log('Login successful, new token issued');
    res.json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/auth/logout', authenticateToken, async (req, res) => {
  try {
    console.log(`User logout initiated for user ID: ${req.user.id}`);
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    user.activeToken = null;
    await user.save();

    io.to(user._id.toString()).emit('logout', { message: 'You have been logged out' });
    console.log('Logout successful');
    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Error during logout:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/protected', authenticateToken, (req, res) => {
  console.log('Accessing protected route');
  res.json({ message: 'Protected route accessed' });
});

function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      console.log('Token verification failed');
      return res.sendStatus(403);
    }
    const user = await User.findById(decoded.id);
    if (!user || user.activeToken !== token) {
      console.log('Invalid or expired token');
      return res.status(401).json({ message: 'Token is no longer valid. Please log in again.' });
    }
    req.user = decoded;
    next();
  });
}

io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('register', (userId) => {
    if (userId) {
      socket.join(userId); 
      console.log(`User ${userId} has joined their room`);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

server.listen(process.env.PORT || 5000, () => {
  console.log(`Server is running on port ${process.env.PORT || 5000}`);
});

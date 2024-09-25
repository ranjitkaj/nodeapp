const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 30 * 60 * 1000 }  // Session expires in 30 minutes
}));

const users = [];

// Helper function to find user by username
function findUser(username) {
  return users.find(user => user.username === username);
}

// Registration route
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (findUser(username)) {
    return res.status(400).send('User already exists');
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    username,
    password: hashedPassword,
    role  // 'admin' or 'user'
  };
  users.push(newUser);

  res.send(`${role.charAt(0).toUpperCase() + role.slice(1)} registered successfully!`);
});

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = findUser(username);
  if (!user) {
    return res.status(400).send('Invalid username or password');
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).send('Invalid username or password');
  }

  req.session.user = {
    username: user.username,
    role: user.role
  };

  res.send(`${user.role.charAt(0).toUpperCase() + user.role.slice(1)} logged in successfully!`);
});

// Admin and user authentication middleware
function adminAuth(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') {
    next();
  } else {
    res.status(403).send('Access denied. Admins only.');
  }
}

function userAuth(req, res, next) {
  if (req.session.user && req.session.user.role === 'user') {
    next();
  } else {
    res.status(403).send('Access denied. Users only.');
  }
}

// Admin dashboard (protected)
app.get('/admin/dashboard', adminAuth, (req, res) => {
  res.send('Welcome to the admin dashboard!');
});

// User dashboard (protected)
app.get('/user/dashboard', userAuth, (req, res) => {
  res.send('Welcome to the user dashboard!');
});

// Logout route
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Failed to log out');
    }
    res.send('Logged out successfully!');
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

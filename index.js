const express = require('express');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

const secretKey = 'manikpuri'; // Secret key for JWT signing
const sessionSecret = 'dageshwar'; // Secret key for session encryption

// Session middleware
app.use(session({
  secret: sessionSecret, // Secret key for session
  resave: false,         // Don't save session if unmodified
  saveUninitialized: false, // Don't create session until something is stored
  cookie: { 
    httpOnly: true,   // Makes the session cookie HTTP-only
    secure: false,    // Set to 'true' in production (HTTPS), false for local development (HTTP)
    maxAge: 60 * 60 * 1000, // 1 hour expiration time
    sameSite: 'strict', // Prevent CSRF
  }
}));

// JWT Route (for handling login and setting JWT)
app.get('/login', (req, res) => {
  const user = { id: 1, username: 'dageshwar das is here' }; // Replace with real user auth

  // Generate JWT token
  const token = jwt.sign(user, secretKey, { expiresIn: '1h' });

  // Set the JWT token in a session cookie
  req.session.jwtToken = token;

  res.send('JWT token stored in session.');
});

// Protected route that requires authentication (using session)
app.get('/protected', (req, res) => {
  const token = req.session.jwtToken; // Retrieve JWT from session

  if (!token) {
    return res.status(401).send('Access denied. No token provided.');
  }

  // Verify the JWT token
  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).send('Invalid token.');

    res.send(`Hello ${user.username}, you are authenticated via session!`);
  });
});

// Logout route to clear the session
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).send('Failed to log out.');
    }
    res.clearCookie('connect.sid').send('Logged out and session cleared.');
  });
});

app.listen(8000, () => console.log('Server running on port 8000'));

const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cookieParser());

const secretKey = 'dageshwarDas';

app.post('/login', (req, res) => {
  const user = { id: 1, username: 'Dageshwar Das' }; 

  const token = jwt.sign(user, secretKey, { expiresIn: '1h' });

  // Set the JWT in an HTTP-only, secure cookie
  res.cookie('token', token, {
    httpOnly: true,  
    secure: true,    
    sameSite: 'strict', 
    maxAge: 60 * 60 * 1000 
  }).send('JWT token sent via cookie');
});

function authenticateToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send('Access denied. No token provided.');

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).send('Invalid token.');
    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.send(`Hello ${req.user.username}, you are authenticated!`);
});

// Logout route to clear the cookie
app.post('/logout', (req, res) => {
  res.clearCookie('token').send('Logged out');
});

app.listen(8000, () => console.log('Server running on port 8000'));

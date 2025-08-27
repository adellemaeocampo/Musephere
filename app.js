var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const { OAuth2Client } = require('google-auth-library');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
const authRouter = require('./routes/auth');

var app = express();
const client = new OAuth2Client('115531890549-d3tfh22ar4fl8o5c9uh1ffc2mkpfqa44.apps.googleusercontent.com');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Default explore.html
app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, 'public', 'Explore.html'));
});

// Google OAuth endpoint
app.post('/api/auth/google', async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: '115531890549-d3tfh22ar4fl8o5c9uh1ffc2mkpfqa44.apps.googleusercontent.com'
    });
    const payload = ticket.getPayload();
    const userId = payload['sub'];

    // Check if the user exists in your database or create a new user
    // For now, just return the payload
    res.json({ success: true, user: payload });
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
});

app.use('/', indexRouter);
app.use('/users', usersRouter);
app.use('/api/auth', authRouter);

module.exports = app;

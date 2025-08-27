const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const router = express.Router();
// O-auth 2 client setup
const client = new OAuth2Client('115531890549-d3tfh22ar4fl8o5c9uh1ffc2mkpfqa44.apps.googleusercontent.com');

router.post('/google', async (req, res) => {
  const { token } = req.body;

  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: '115531890549-d3tfh22ar4fl8o5c9uh1ffc2mkpfqa44.apps.googleusercontent.com'
    });
    const payload = ticket.getPayload();
    const userId = payload['sub'];

    // Check if the user exists in your database or create a new user
    res.json({ success: true, user: payload });
  } catch (error) {
    res.status(401).json({ success: false, error: 'Invalid token' });
  }
});

module.exports = router;
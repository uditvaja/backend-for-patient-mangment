const express = require('express');
const router = express.Router();
const tokenController = require('../../../src/controllers/videoCall/tokenController');

// POST request to generate ZEGOCLOUD token
router.post('/getZegoToken', tokenController.generateZegoToken);

module.exports = router;

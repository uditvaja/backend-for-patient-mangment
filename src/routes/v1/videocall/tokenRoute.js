const express = require('express');
const router = express.Router();
const tokenController = require('../../../controllers/videoCall/tokenController');

// POST request to generate ZEGOCLOUD token
router.post('/getZegoToken', tokenController.generateZegoToken);

module.exports = router;

const ZegoToken = require('../../models/zegoTokenModel');

// Controller to handle token generation
exports.generateZegoToken = async (req, res) => {
    try {
        const { userID, roomID, action, userName } = req.body;

        if (!userID || !roomID || !action || !userName) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Generate the ZEGOCLOUD token and store it in the database
        const token = await ZegoToken.generateToken(userID, roomID, action, userName);

        // Send response back with generated token and user details
        return res.status(200).json({ token, roomID, userName, userID });
    } catch (error) {
        return res.status(500).json({ error: 'Error generating token' });
    }
};

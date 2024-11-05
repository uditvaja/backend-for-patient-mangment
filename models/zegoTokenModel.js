const mongoose = require('mongoose');

// Define a schema for ZegoToken
const ZegoTokenSchema = new mongoose.Schema({
    token: String,
    userID: String,
    userName: String,
    roomID: String,
    action: String,
    createdAt: { type: Date, default: Date.now },
});

// Create a model from the schema
const ZegoTokenModel = mongoose.model('ZegoToken', ZegoTokenSchema);

// Logic to generate token and save it to the database
class ZegoToken {
    static async generateToken(userID, roomID, action, userName) {
        const crypto = require('crypto');
        
        // Generate token (mock)
        const token = crypto.randomBytes(16).toString('hex');
        
        // Save token data to the database
        const zegoTokenData = new ZegoTokenModel({
            token,
            userID,
            userName,
            roomID,
            action,
        });

        // Save to the database and return the token
        await zegoTokenData.save();
        return token;
    }
}

module.exports = ZegoToken;

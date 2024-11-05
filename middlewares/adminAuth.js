const jwt = require("jsonwebtoken");
const Admin = require("../models/admin.model");
const { queryErrorRelatedResponse } = require("../helpers/sendresponse");


/*************  ✨ Codeium Command ⭐  *************/
/**
 * Verify the admin authentication token.
 * @function
 * @param {Object} req - Request object.
 * @param {Object} res - Response object.
 * @param {function} next - Next middleware.
 */
/******  1bb155f3-bb69-4dad-a51d-3d6e91cbf60c  *******/
module.exports = async function (req, res, next) {
    let token = req.header("Authorization");
    
    if (token) {
        token = req.header("Authorization").replace("Bearer ", "");
    }
    
    if (!token) return queryErrorRelatedResponse(req, res, 402, "Access Denied.");
    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET_KEY);
        
        let admin = await Admin.findOne({email : verified.email});
        if (!admin) {
            return queryErrorRelatedResponse(req, res, 402, "Access Denied.");
        }
        
        req.admin = admin;
        req.token = token;
        next();
    } catch (error) {
        queryErrorRelatedResponse(req, res, 402, "Invalid Token.")
    }
};
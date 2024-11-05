const express = require("express");
const router = express.Router();
const {  dashboardController } = require("../../../src/controllers");
const authenticAdmin = require("../../../middlewares/adminAuth");
const { singleFileUpload, multiDiffFileUpload } = require("../../../src/helpers/upload");
const { adminAuthValidation } = require("../../../validations");
const validate = require("../../../middlewares/validate");


router.get("/search-doctor-and-patient-list",
    authenticAdmin, 
    dashboardController.searchDoctorAndPatientist);




module.exports = router;


/* ------------------------------- DEFINE AREA ------------------------------ */
const express = require("express");
const router = express.Router();

// const { singleFileUpload } = require("../../../../helpers/upload");
const {  hospitalController } = require("../../../controllers");



/* -------------------------- CREATE/SIGNUP DOCTOR ----------- */
router.post("/create-hospital", hospitalController.createHospital);
router.get("/get-hospitals", hospitalController.getHospitals);


module.exports = router;

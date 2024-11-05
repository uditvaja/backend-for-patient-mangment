
/* ------------------------------- DEFINE AREA ------------------------------ */
const express = require("express");
const router = express.Router();

// const { singleFileUpload } = require("../../../../helpers/upload");
const {   prescriptionController, precriptionPatientController, uploadFileOfPrescriptionController } = require("../../../controllers");
const { singleFileUpload } = require("../../../helpers/upload");


// ----------------------------------------START-----------------------------------------------------------------------------------
/* -------------------------- DOCTOR FLOW ======PRESCRIPTION TOOLS-------->CREATE ----------- */
router.post("/create-prescription", prescriptionController.createPrescription);
// ----------------------------------------END------------------------------------------------------------------------------------


// ----------------------------------------START------------------------------------------------------------------------------------
// ---------------------------------------doctor flow prescription upload files of prescription----------------------------------------------------------------------------------------------------------
router.post("/create-prescription-file-upload", singleFileUpload('/prescriptionImg','image') ,uploadFileOfPrescriptionController.createImageAndDescription);
router.get("/view-prescription-file-upload",uploadFileOfPrescriptionController.viewRecordOfUploadFile);
router.get("/over-view-prescription-file-upload",uploadFileOfPrescriptionController.overViewRecordOfUploadFile);
router.get("/description-view-prescription",uploadFileOfPrescriptionController.viewFullPrescription);
router.get("/full-view-prescription",uploadFileOfPrescriptionController.fullviewPrescription);
//---------------------------------------------END-------------------------------------------------------------------------------------------------


// ------------------------------ START--------------------------------------------------------------------------
//  doctor flow ======= patient record access panel ma------> 2nd page 
router.get('/list-patient-id',prescriptionController.patientDetailFromDoctorIdInDoctorFlowAppointments);
// ------------------------------ END--------------------------------------------------------------------------


// ------------------------------ START--------------------------------------------------------------------------
// doctor folw ============== prescription tools panel ma --------->mange 
router.get('/list-patient-id-prescription-old',prescriptionController.getOldPrescriptionDetails);
router.get('/list-patient-all-appointment',prescriptionController.getAllAppointments);
router.get("/all-view-prescription",uploadFileOfPrescriptionController.fullviewPrescription);

// ------------------------------ END--------------------------------------------------------------------------

// ----------------------------------------START------------------------------------------------------------------------------------
// --------------------------------DOCTOR FLOW---------------EXACT PRESCRIPTION TOOLS PANEL---------
router.get('/list-patient-all-appointment-searchinf-fromdate-todate',prescriptionController.getAppointmentsByDateRange);
// ----------------------------------------END------------------------------------------------------------------------------------

router.get('/prescriptions-patient-id',prescriptionController.getPrescriptionsByPatientId);

router.get('/list-patient-id-prescription',prescriptionController.getPrescriptionDetailsByPatientId);

//  patient flow --------prescription access 
router.get('/prescriptions-patient-id-list',precriptionPatientController.getPrescriptionsByPatientId);
router.get("/patient-flow-all-view-prescription",precriptionPatientController.fullviewPrescription);
router.get("/searching-prescriptions-patient-id-list",precriptionPatientController.fullviewPrescriptionBySearchDateRangeWise);




module.exports = router;


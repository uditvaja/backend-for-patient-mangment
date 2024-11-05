
/* ------------------------------- DEFINE AREA ------------------------------ */
const express = require("express");
const router = express.Router();

// const { singleFileUpload } = require("../../../../helpers/upload");
const { patintFlowBookappointmentController } = require("../../../controllers");
const authenticPatient = require("../../../middlewares/patientAuth");



/* -------------------------- CREATE/SIGNUP DOCTOR ----------- */
router.get("/bookappointement-today-list-appointement-book",authenticPatient, patintFlowBookappointmentController.getTodaysAppointmentsForPatient);
router.get("/searching-bookappointement-today-list-appointement-book",authenticPatient, patintFlowBookappointmentController.getAppointmentsForPatientInRange);
router.get("/bookappointement-today-appointement-doctor-details-list",authenticPatient, patintFlowBookappointmentController.getPatientAppointmentsWithDoctor);
router.post("/bookappointement-cancel", patintFlowBookappointmentController.cancelAppointment);

router.get("/bookappointement-previous-list-appointement-book",authenticPatient, patintFlowBookappointmentController.getPreviousAppointmentsForPatient);
router.get("/searching-bookappointement-previous-list-appointement-book",authenticPatient, patintFlowBookappointmentController.getPreviousAppointmentsForPatientInRange);
router.get("/bookappointement-previous-appointement-doctor-details-list",authenticPatient, patintFlowBookappointmentController.getPatientAppointmentsWithDoctorPrevious);

router.get("/bookappointement-cancel-list-appointement-book",patintFlowBookappointmentController.getCanceledAppointments);
// router.get("/searching-bookappointement-cancel-list-appointement-book", patintFlowBookappointmentController.getCanceledAppointmentsInRange);
router.get("/bookappointement-cancel-appointement-doctor-details-list",authenticPatient, patintFlowBookappointmentController.getPatientAppointmentsWithDoctorcancel);


router.get("/bookappointement-pending-list-appointement-book",authenticPatient, patintFlowBookappointmentController.getPendingAppointments);
router.get("/searching-bookappointement-pending-list-appointement-book", patintFlowBookappointmentController.getPendingAppointmentsInRange);
router.get("/bookappointement-pending-appointement-doctor-details-list",authenticPatient, patintFlowBookappointmentController.getPatientAppointmentsWithDoctorPending);


module.exports = router;



/* ------------------------------- DEFINE AREA ------------------------------ */
const express = require("express");
const   router = express.Router();

// const { singleFileUpload } = require("../../../../helpers/upload");
const {  telecommunicationControllerPatientFlow } = require("../../../src/controllers");



/* -------------------------- CREATE/SIGNUP DOCTOR ----------- */
router.get("/telecom-schedule-appointment-patient", telecommunicationControllerPatientFlow.getTodayAppointmentsForPatient);
router.get("/telecom-schedule-appointment-patient-search", telecommunicationControllerPatientFlow.getAppointmentsWithinDateRange);
router.get("/telecom-upcomming-appointment-search-patient-name-patient-flow", telecommunicationControllerPatientFlow.getUpcomingAppointmentsSearchForPatient);
router.get("/telecom-previous-appointment-patient", telecommunicationControllerPatientFlow.getPreviousAppointmentsForPatient);
router.get("/telecom-previous-appointment-search-patient-name-patient-flow", telecommunicationControllerPatientFlow.getPreviousAppointmentsSearchForPatient);
router.post("/telecom-cancel-appointment-patient", telecommunicationControllerPatientFlow.cancelAppointment);
router.get("/telecom-cancel-appointment-search-patient-name", telecommunicationControllerPatientFlow.getCanceledAppointmentsSearchForPatient);
router.get("/telecom-after-join-call-appointment-reminder-patient", telecommunicationControllerPatientFlow.getAppointmentDetailsByIdForPatient);
router.get("/telecom-after-join-call-appointment-reminder-patient-details", telecommunicationControllerPatientFlow.getAppointmentDetailsOfPatientByIdForPatient);

router.put('/telecom-create-call-patient', telecommunicationControllerPatientFlow.updateJoinCallForPatient);






module.exports = router;

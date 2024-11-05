
/* ------------------------------- DEFINE AREA ------------------------------ */
const express = require("express");
const router = express.Router();

// const { singleFileUpload } = require("../../../../helpers/upload");
const { dashboardController } = require("../../../../controllers");
const authenticAdmin = require("../../../../middlewares/adminAuth");

 
/* -------------------------- CREATE/SIGNUP DOCTOR ----------- */

// DOCTOR MANAGEMENT PANNEL
router.get("/doctor-list",authenticAdmin, dashboardController.allDoctorList);
// Update the route to POST method
router.post("/doctor-list-id", authenticAdmin, dashboardController.allDoctorListId);

router.get("/doctor-list-search-doctor",authenticAdmin, dashboardController.searchDoctor);
router.delete("/doctor-list-delete",authenticAdmin, dashboardController.deleteDoctor);



router.get("/appointement-today", dashboardController.getTodayAppointments);
router.get("/appointement-upcomming", dashboardController.getUpcomingAppointments);
router.get("/appointement-previous", dashboardController.getPreviousAppointments);
router.get("/appointement-cancel", dashboardController.getCanceledAppointments);
router.get("/appointement-wise-patient-detail-id", dashboardController.getAppointmentDetailsOfPatientById);



// this is pending work
// router.get("/appointement-today-search", dashboardController.getTodayAppointmentsSearch);
// router.get("/appointement-upcomming-search", dashboardController.getUpcomingAppointmentsSearch);
// router.get("/appointement-previous-search", dashboardController.getPreviousAppointmentsSearch);
// router.get("/appointement-cancel-search", dashboardController.getCanceledAppointmentsSearch);





module.exports = router;

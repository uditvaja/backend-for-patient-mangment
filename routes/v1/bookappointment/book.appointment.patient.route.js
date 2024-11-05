
const express = require("express");
const router = express.Router();
const {   bookapointmentPatientController, doctorFlowAppointmentController } = require("../../../src/controllers");
const authenticPatient = require("../../../middlewares/patientAuth");
const authenticDoctor = require("../../../middlewares/doctorAuth");

// not understand of authentication,and response :-  bookapointmentPatientController,



// -----------------------------------------------START----------------------------------------------------------
// ****************************************** -- DOCTOR FLOW --  **************************************************
// ======================= 1.APPOINTMENT MANAGEMENT

router.get("/doctorflow-today-appointmentbook-date",
authenticDoctor, 
doctorFlowAppointmentController.getTodayAppointments);

router.get("/doctorflow-upcoming-appointmentbook-date",
    authenticDoctor, 
    doctorFlowAppointmentController.getUpcomingAppointments);

    
router.get("/doctorflow-previous-appointmentbook-date",
    authenticDoctor, 
    doctorFlowAppointmentController.getPreviousAppointments);

    
router.get("/doctorflow-cancel-appointmentbook-date",
    authenticDoctor, 
    doctorFlowAppointmentController.getCanceledAppointments);

    router.delete("/doctorflow-delete-appointment-timeslot",
        authenticDoctor, 
        doctorFlowAppointmentController.deleteAppDateAndTimeSlot);

        router.put("/doctorflow-update-appointment-timeslot-date",
            authenticDoctor, 
            doctorFlowAppointmentController.updateAppointmentDetails);


            router.get("/searching-fromdate-todate-doctor",
                authenticDoctor, 
                doctorFlowAppointmentController.getAppointmentsByDateRange);

                router.post("/create-notes-date-time",
                    authenticDoctor, 
                    doctorFlowAppointmentController.createAppointmentNote);
                    
                    
                    // docotr flow in dash board ------------PATIENT RECORD ACCESS PANEL
                router.get('/patient-record-access',authenticDoctor,doctorFlowAppointmentController.getDetailsPatients)
                router.get('/patient-record-access-seraching-month',authenticDoctor,doctorFlowAppointmentController.getDetailsPatientsSearching)
                
                
                router.get('/patient-record-access-doctor-id',authenticDoctor,doctorFlowAppointmentController.patientDetailFromDoctorIdInDoctorFlowAppointments)
                
                router.get('/patient-id-their-all-appointment-list',authenticDoctor,doctorFlowAppointmentController.getAppointmentsByDoctor)

                router.get("/all-appointment-of-patient",
                    // authenticDoctor, 
                    doctorFlowAppointmentController.getAllAppointments);

                    




router.post("/create-appointment-book",
    // authenticPatient, 
    bookapointmentPatientController.bookAppointment);

    
    
router.post("/create-cancel-appointment",
    authenticDoctor, 
    bookapointmentPatientController.cancelAppointment);

    router.get("/docotr-list-by-id",
        authenticDoctor, 
        bookapointmentPatientController.doctorList);

        router.get("/appointment-previous",
            // authenticDoctor, 
            bookapointmentPatientController.appointmentListById);


            router.get("/appointment-list-cancel-date",
                authenticDoctor, 
                bookapointmentPatientController.appointmentTypeOnlineList);

                router.get("/appointment-list-pending-status-patient",
                    authenticDoctor, 
                    bookapointmentPatientController.appointmentTypeOnlineList);



                                    

                                    // router.get("/details-of-patient",
                                    //     authenticDoctor, 
                                    //     doctorFlowAppointmentController.getAllAppointments);




    
module.exports = router;

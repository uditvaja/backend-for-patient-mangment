/* ------------------------------- DEFINE AREA ------------------------------ */
const express = require("express");
const router = express.Router();
const {
  doctorAuthController,
  doctorOwnController,
  doctorTimeSlotController,
  doctorFlowAppointmentController,
} = require("../../../src/controllers");
const authenticDoctor = require("../../../middlewares/doctorAuth");
const { singleFileUpload, multiDiffFileUpload } = require("../../../src/helpers/upload");
const multer = require('multer');

/* ------------------------------- DOCTOR AUTH ------------------------------ */

// Login Doctor
router.post("/doctor-login", doctorAuthController.login);

// Forgot Password Doctor
router.post("/forgot-pass", doctorAuthController.forgotPass);

// Verify OTP Doctor
router.post("/verify-otp", doctorAuthController.verifyOtp);

// Reset Password Doctor
router.put("/reset-password", doctorAuthController.resetPassword);

// Change Password Doctor
router.post("/change-password", authenticDoctor, doctorAuthController.changePassword);

// Create Time Slot
router.post("/create-time-slot", doctorTimeSlotController.createTimeSlot);

// Get All Doctors
router.get("/get-all-doctors", doctorAuthController.getAllDoctors);


const storage = multer.memoryStorage(); // Use memory storage for direct upload to Cloudinary
const upload = multer({ storage: storage });

// Update Doctor Profile
router.put(
  '/update-doctor',
  authenticDoctor,
  upload.fields([
    { name: 'image', maxCount: 1 }, // Field name for doctor's image
  ]),
  doctorOwnController.updateDoctor
);

module.exports = router;

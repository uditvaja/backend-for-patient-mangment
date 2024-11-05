const AppointmentBook = require("../../models/bookAppointment.model");
const Doctor = require("../../models/doctor.model");
const Hospital = require("../../models/hospital.model");
const Patient = require("../../models/patient.model");
const Prescription = require("../../models/prescription.model");
const moment = require('moment-timezone')
const getPrescriptionsByPatientId = async (req, res) => {
    try {
        const { patientId } = req.body; // Get patientId from the request body
  
        // Fetch all appointments for the given patientId and populate doctor and hospital details
        const appointments = await AppointmentBook.find({ patientId })
            .populate('doctorId', 'firstName') // Populate doctor's first name
            .populate('hospitalId', 'hospitalName'); // Populate hospital's name
  
        if (!appointments || appointments.length === 0) {
            return res.status(404).json({
                status: 404,
                message: "No appointments found for the given patient",
                success: false,
            });
        }
  
        // Get all appointment IDs
        const appointmentIds = appointments.map(appointment => appointment._id);
  
        // Fetch prescriptions that match any of the appointment IDs
        const prescriptions = await Prescription.find({ appointmentId: { $in: appointmentIds } });
  
        if (!prescriptions || prescriptions.length === 0) {
            return res.status(404).json({
                status: 404,
                message: "No prescriptions found for the given patient",
                success: false,
            });
        }
  
        // Combine prescriptions with relevant appointment details
        const detailedPrescriptions = prescriptions.map(prescription => {
            // Find the corresponding appointment for each prescription
            const appointment = appointments.find(app => app._id.toString() === prescription.appointmentId.toString());
            return {
                prescriptionId: prescription._id,
                doctorFirstName: appointment.doctorId.firstName, // Doctor's first name
                hospitalName: appointment.hospitalId.hospitalName, // Hospital name
                diseaseName: prescription.disease_name, // Assuming `disease_name` is a field in the Prescription model
                app_date: appointment.app_date, // Appointment date
                startTime: moment(appointment.startTime).tz("Asia/Kolkata").format("h:mm A"), // Formatted start time
                endTime: moment(appointment.endTime).tz("Asia/Kolkata").format("h:mm A") // Formatted end time
            };
        });
  
        res.status(200).json({
            status: 200,
            message: "Successfully fetched all prescriptions",
            success: true,
            data: detailedPrescriptions,
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

const fullviewPrescription = async (req, res) => {
    try {
      const { prescriptionId } = req.body;
  
      // Fetch the prescription and populate the necessary fields
      const prescription = await Prescription.findById(prescriptionId)
        .populate({
          path: 'appointmentId',
          populate: [
            {
              path: 'doctorId',
              model: Doctor,
              select: 'firstName specialistType signatureImage', // Fetch doctor's details
            },
            {
              path: 'patientId',
              model: Patient,
              select: 'first_name age patient_address gender', // Fetch patient's details
            },
            {
              path: 'hospitalId',
              model: Hospital,
              select: 'hospital_name hospital_logo', // Fetch hospital's details
            },
          ],
        })
        .select('description date additional_notes mdecinename strenght dose duration when_to_take'); // Include prescription fields
  
      if (!prescription) {
        return res.status(404).json({ message: 'Prescription not found' });
      }
  
      // Extract required data from prescription
      const { appointmentId, description, additional_notes, date, mdecinename, strenght, dose, duration, when_to_take } = prescription;
      const doctorFirstName = appointmentId.doctorId.firstName;
      const doctorSpecialistType = appointmentId.doctorId.specialistType;
      const doctorSignatureImage = appointmentId.doctorId.signatureImage;
  
      const patient = appointmentId.patientId;
      const hospitalName = appointmentId.hospitalId.hospital_name;
      const hospitalLogo = appointmentId.hospitalId.hospital_logo;
  
      // Prepare response data
      const responseData = {
        doctorFirstName,
        doctorSpecialistType,
        doctorSignatureImage,
        hospitalName,
        hospitalLogo,
        patientFirstName: patient.first_name,
        patientAge: patient.age,
        patientAddress: patient.patient_address,
        patientGender: patient.gender,
        prescriptionDescription: description,
        prescriptionAdditionalNotes: additional_notes,
        prescriptionDate: date,
        medicineNames: mdecinename, // Medicine names array
        strengths: strenght, // Strengths array
        doses: dose, // Doses array
        durations: duration, // Durations array
        whenToTake: when_to_take, // When to take medicine array
      };
  
      return res.status(200).json(responseData);
    } catch (error) {
      console.error('Error:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  };

  const fullviewPrescriptionBySearchDateRangeWise = async (req, res) => {
    try {
      const { prescriptionId, fromDate, toDate } = req.body;
  
      // Create a date range filter if both fromDate and toDate are provided
      const dateFilter = {};
      if (fromDate && toDate) {
        dateFilter.date = {
          $gte: new Date(fromDate), // Greater than or equal to fromDate
          $lte: new Date(toDate), // Less than or equal to toDate
        };
      }
  
      // Fetch the prescription and populate the necessary fields, apply the date filter
      const prescription = await Prescription.find({
        // _id: prescriptionId,
        ...dateFilter, // Apply the date filter here
      })
        .populate({
          path: 'appointmentId',
          populate: [
            {
              path: 'doctorId',
              model: Doctor,
              select: 'firstName specialistType signatureImage', // Fetch doctor's details
            },
            {
              path: 'patientId',
              model: Patient,
              select: 'first_name age patient_address gender', // Fetch patient's details
            },
            {
              path: 'hospitalId',
              model: Hospital,
              select: 'hospital_name hospital_logo', // Fetch hospital's details
            },
          ],
        })
        .select('description date additional_notes mdecinename strenght dose duration when_to_take'); // Include prescription fields
  
      if (!prescription || prescription.length === 0) {
        return res.status(404).json({ message: 'Prescription not found in the specified date range' });
      }
  
      // Extract required data from prescription
      const { appointmentId, description, additional_notes, date, mdecinename, strenght, dose, duration, when_to_take } = prescription[0]; // Access the first prescription if there's more than one
      const doctorFirstName = appointmentId.doctorId.firstName;
      const doctorSpecialistType = appointmentId.doctorId.specialistType;
      const doctorSignatureImage = appointmentId.doctorId.signatureImage;
  
      const patient = appointmentId.patientId;
      const hospitalName = appointmentId.hospitalId.hospital_name;
      const hospitalLogo = appointmentId.hospitalId.hospital_logo;
  
      // Prepare response data
      const responseData = {
        doctorFirstName,
        doctorSpecialistType,
        doctorSignatureImage,
        hospitalName,
        hospitalLogo,
        patientFirstName: patient.first_name,
        patientAge: patient.age,
        patientAddress: patient.patient_address,
        patientGender: patient.gender,
        prescriptionDescription: description,
        prescriptionAdditionalNotes: additional_notes,
        prescriptionDate: date,
        medicineNames: mdecinename, // Medicine names array
        strengths: strenght, // Strengths array
        doses: dose, // Doses array
        durations: duration, // Durations array
        whenToTake: when_to_take, // When to take medicine array
      };
  
      return res.status(200).json(responseData);
    } catch (error) {
      console.error('Error:', error);
      return res.status(500).json({ message: 'Server error' });
    }
  };
  
  
module.exports = {
    getPrescriptionsByPatientId,fullviewPrescription,fullviewPrescriptionBySearchDateRangeWise
}
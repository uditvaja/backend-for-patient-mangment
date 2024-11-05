const AppointmentBook = require("../../models/bookAppointment.model");
const Doctor = require("../../models/doctor.model");
const Hospital = require("../../models/hospital.model");
const Patient = require("../../models/patient.model");
const Prescription = require("../../models/prescription.model");
const cloudinary = require('cloudinary').v2;
const mongoose = require('mongoose')

const createImageAndDescription = async (req, res) => {
  try {
    const { description, prescriptionId } = req.body; // Get description and prescriptionId from request body

    // Check if prescriptionId is provided
    if (!prescriptionId) {
      return res.status(400).json({ success: false, message: 'Prescription ID is required.' });
    }

    // Find the Prescription by its ID
    const prescription = await Prescription.findById(prescriptionId);
    if (!prescription) {
      return res.status(404).json({ success: false, message: 'Prescription not found.' });
    }

    // Function to upload image to Cloudinary
    const uploadImage = async (file) => {
      if (file) {
        // Upload the image to Cloudinary
        const uploadResponse = await cloudinary.uploader.upload(file.path, {
          folder: 'prescriptionImages', // Define the folder in Cloudinary
        });

        // Return the uploaded image details
        return {
          public_id: uploadResponse.public_id,
          url: uploadResponse.secure_url,
        };
      }
      return null; // Return null if no file is provided
    };

    // Check if an image file is provided in the request
    const newImage = await uploadImage(req.file);

    // Handle case when image is missing
    if (!newImage) {
      return res.status(400).json({ success: false, message: 'Image is required.' });
    }

    // Handle case when description is missing
    if (!description) {
      return res.status(400).json({ success: false, message: 'Description is required.' });
    }

    // Update the prescription record with the new image and description
    prescription.image = newImage;
    prescription.description = description;

    // Save the updated record to the database
    const updatedPrescription = await prescription.save();

    // Respond with success
    return res.status(200).json({
      success: true,
      message: 'Image and description updated successfully.',
      data: updatedPrescription,
    });
  } catch (err) {
    // Handle errors
    return res.status(400).json({ success: false, error: err.message });
  }
};


const viewRecordOfUploadFile = async (req, res) => {
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
                        select: 'firstName' // Adjust the field name as necessary
                    },
                    {
                        path: 'patientId',
                        model: Patient,
                        select: 'first_name age patient_address dob' // Adjust the field names as necessary
                    },
                    {
                        path: 'hospitalId',
                        model: Hospital,
                        select: 'hospital_name' // Adjust the field name as necessary
                    }
                ]
            })
            .select('description');

        if (!prescription) {
            return res.status(404).json({ message: 'Prescription not found' });
        }

        // Extract required data
        const { appointmentId, description } = prescription;
        const doctorFirstName = appointmentId.doctorId.firstName;
        const patient = appointmentId.patientId;
        const hospitalName = appointmentId.hospitalId.hospital_name;

        // Prepare response data
        const responseData = {
            doctorFirstName,
            hospitalName,
            patientFirstName: patient.first_name,
            patientAge: patient.age,
            patientAddress: patient.patient_address,
            patientDate: patient.dob,

            prescriptionDescription: description,
        };

        return res.status(200).json(responseData);
    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Server error' });
    }
  };


  const overViewRecordOfUploadFile = async (req, res) => {
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
                        select: 'firstName specialistType' // Adjust the field name as necessary
                    },
                    {
                        path: 'patientId',
                        model: Patient,
                        select: 'first_name age patient_address gender' // Adjust the field names as necessary
                    },
                    {
                        path: 'hospitalId',
                        model: Hospital,
                        select: 'hospital_name hospital_logo' // Adjust the field name as necessary
                    }
                ]
            })
            .select('description date');

        if (!prescription) {
            return res.status(404).json({ message: 'Prescription not found' });
        }

        // Extract required data
        const { appointmentId, description,date} = prescription;
        const doctorFirstName = appointmentId.doctorId.firstName;
        const doctorSpecialistType = appointmentId.doctorId.specialistType;
        const patient = appointmentId.patientId;
        const hospitalName = appointmentId.hospitalId.hospital_name;
        const hospitalLogo = appointmentId.hospitalId.hospital_logo;

        // Prepare response data
        const responseData = {
            doctorFirstName,
            doctorSpecialistType,
            hospitalLogo,
            hospitalName,
            patientFirstName: patient.first_name,
            patientAge: patient.age,
            patientAddress: patient.patient_address,
            patientGender: patient.gender,
            prescriptionDescription: description,
            prescriptionDescriptionDate: date,

        };

        return res.status(200).json(responseData);
    } catch (error) {
        console.error('Error:', error);
        return res.status(500).json({ message: 'Server error' });
    }
  };

  const viewFullPrescription = async (req, res) => {
    try {
        const { prescriptionId } = req.body;  // Assuming prescriptionId is passed as a route parameter

        // Find the prescription by its ID and select the 'description' field
        const prescription = await Prescription.findById(prescriptionId).select('description');

        if (!prescription) {
            return res.status(404).json({ message: 'Prescription not found' });
        }

        // Prepare the response with just the prescription description
        const responseData = {
            prescriptionDescription: prescription.description
        };

        return res.status(200).json(responseData);
    } catch (error) {
        // console.error('Error:', error);
        return res.status(500).json({ message: 'Server error' });
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

module.exports = {
  createImageAndDescription,viewRecordOfUploadFile,overViewRecordOfUploadFile,viewFullPrescription,fullviewPrescription
};


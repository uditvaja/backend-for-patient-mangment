const Admin = require("../../models/admin.model");
const AppointmentBook = require("../../models/bookAppointment.model");
const Doctor = require("../../models/doctor.model");
const Patient = require("../../models/patient.model");
const moment = require('moment-timezone');
const { formatToIST } = require('../../helpers/timeFormat');

const searchDoctorAndPatientist = async (req, res) => {
    try {
      const { query } = req.query;
  
      // Check if query parameter is provided
      if (!query) {
        return res.status(404).json({
          status: 404,
          success: false,
          message: "Query parameter is missing.",
        });
      }
      // Use a regular expression for case-insensitive search
      const regex = new RegExp(query, "i");
  
      // Search in Doctor model
      const doctorResults = await Doctor.find({
        firstName: regex, // Adjust to match the field you are searching against
      });
  
      // Search in Specialist model
      const specialistResults = await Patient.find({
        first_name: regex, // Adjust to match the field you are searching against
      });
  
      // Combine the results from both models
      const combinedResults = [...doctorResults, ...specialistResults];
  
      if (combinedResults.length === 0) {
        return res.status(404).json({
          status: 404,
          success: false,
          message:
            "No matching doctors or specialists found for the given query.",
        });
      }
      // If results are found, return a success response with the combined search results
      res.status(200).json({
        status: 200,
        success: true,
        message: "Search data retrieved successfully.",
        searchResults: combinedResults,
      });
    } catch (error) {
      // console.error("Error in searchDoctorSpecialist:", error);
      res
        .status(500)
        .json({ status: 500, success: false, error: "Internal Server Error" });
    }
  };

  const searchDoctor = async (req, res) => {
    try {
      const { query } = req.query;
  
      // Check if query parameter is provided
      if (!query) {
        return res.status(404).json({
          status: 404,
          success: false,
          message: "Query parameter is missing.",
        });
      }
      // Use a regular expression for case-insensitive search
      const regex = new RegExp(query, "i");
  
      // Search in Doctor model
      const doctorResults = await Doctor.find({
        firstName: regex, // Adjust to match the field you are searching against
      });
  
      // // Search in Specialist model
      // const specialistResults = await Patient.find({
      //   first_name: regex, // Adjust to match the field you are searching against
      // });
  
      // Combine the results from both models
      const combinedResults = [...doctorResults];
  
      if (combinedResults.length === 0) {
        return res.status(404).json({
          status: 404,
          success: false,
          message:
            "No matching doctors or specialists found for the given query.",
        });
      }
      // If results are found, return a success response with the combined search results
      res.status(200).json({
        status: 200,
        success: true,
        message: "Search data retrieved successfully.",
        searchResults: combinedResults,
      });
    } catch (error) {
      // console.error("Error in searchDoctorSpecialist:", error);
      res
        .status(500)
        .json({ status: 500, success: false, error: "Internal Server Error" });
    }
  };

  const allDoctorList = async (req, res) => {
    try {
      const { adminId } = req.body; // Get the adminId from request body
  
      // Check if adminId is provided
      if (!adminId) {
        return res.status(400).json({ message: 'Admin ID is required.' });
      }
  
      // Check if the adminId exists in the database
      const admin = await Admin.findById(adminId); // Assuming 'Admin' is your model for admins
  
      // If admin is not found, return an error
      if (!admin) {
        return res.status(404).json({ message: 'Admin not found.' });
      }
  
      // If admin exists, proceed to fetch the doctor list
      const doctors = await Doctor.find();
  
      // Send the doctor list with a success message
      res.status(200).json({ success: true, doctors, message: 'All doctor list is done' });
  
    } catch (error) {
      // Handle any errors during the fetching process
      console.error('Error fetching doctors:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  };
  
  const allDoctorListId = async (req, res) => {
    try {
      const { adminId, doctorId } = req.body; // Get adminId and doctorId from request body
  
      // Check if adminId is provided
      if (!adminId) {
        return res.status(400).json({ message: 'Admin ID is required.' });
      }
  
      // Check if the adminId exists in the database
      const admin = await Admin.findById(adminId); // Assuming 'Admin' is your model for admins
  
      // If admin is not found, return an error
      if (!admin) {
        return res.status(404).json({ message: 'Admin not found.' });
      }
  
      // If doctorId is provided, find the particular doctor
      if (doctorId) {
        const doctor = await Doctor.findById(doctorId); // Fetch the specific doctor by ID
  
        // If doctor is not found, return an error
        if (!doctor) {
          return res.status(404).json({ message: 'Doctor not found.' });
        }
  
        // Send the specific doctor details with a success message
        return res.status(200).json({ success: true, doctor, message: 'Doctor found successfully' });
      }
  
      // If no doctorId is provided, fetch all doctors
      const doctors = await Doctor.find();
  
      // Send the doctor list with a success message
      res.status(200).json({ success: true, doctors, message: 'All doctor list is done' });
  
    } catch (error) {
      // Handle any errors during the fetching process
      console.error('Error fetching doctors:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  };
  
  const deleteDoctor = async (req, res) => {
    try {
      const { doctorId, adminId } = req.body; // Assuming adminId is passed for authorization checks
      const admin = await Admin.findById(adminId);
      // Find the doctor by ID
      const doctor = await Doctor.findById(doctorId);
      if (!doctor || !admin) {
        return res.status(404).json({ status: 404, success: false, message: "Doctor or admin not found!" });
      }

      // Delete the doctor's image from Cloudinary if it exists
      if (doctor.image && doctor.image.public_id) {
        await cloudinary.uploader.destroy(doctor.image.public_id);
      }
  
      // Delete the doctor's signature image from Cloudinary if it exists
      if (doctor.signatureImage && doctor.signatureImage.public_id) {
        await cloudinary.uploader.destroy(doctor.signatureImage.public_id);
      }
  
      // Delete the doctor profile from the database
      await Doctor.findByIdAndDelete(doctorId);
  
      // Respond with success
      return res.status(200).json({
        status: 200,
        success: true,
        message: "Doctor profile deleted successfully",
      });
  
    } catch (err) {
      // Handle errors
      return res.status(400).json({ success: false, error: err.message });
    }
  };
  
  const getTodayAppointments = async (req, res) => {
    try {
              // Get doctorId from request
              const { adminId } = req.query;

              // Validate doctorId
              if (!adminId) {
                  return res.status(400).json({ message: 'adminId is required.' });
              }
      
              // Check if the doctor exists
              const adminExists = await Admin.findById(adminId);
              if (!adminExists) {
                  return res.status(404).json({ message: 'admin not found.' });
              }

        // Get today's date in 'YYYY-MM-DD' format
        const today = moment().format('YYYY-MM-DD');

        // Find all appointments where app_date matches today
        const todayAppointments = await AppointmentBook.find({
            app_date: today
        })
        .select('appointmentType app_date patient_issue diseas_name startTime') // Adjust fields as needed
        .populate('patientId', 'first_name last_name')
        .populate('doctorId', 'firstName');


        // Check if any appointments were found
        if (!todayAppointments.length) {
            return res.status(404).json({ message: 'No appointments found for today.' });
        }

        // Format the startTime to Indian Standard Time (IST) for each appointment
        const formattedAppointments = todayAppointments.map(appointment => {
            const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST in 'h:mm A' format
            return {
                ...appointment.toObject(),
                startTime: startTimeIST  // Overwrite startTime with formatted IST time
            };
        });

        // Return the list of today's appointments with formatted time
        return res.status(200).json({
            message: 'Today\'s appointments retrieved successfully.',
            appointments: formattedAppointments
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'An error occurred while retrieving today\'s appointments.' });
    }
};

const getUpcomingAppointments = async (req, res) => {
  try {

        // Get doctorId from request
        const { adminId } = req.query;

        // Validate doctorId
        if (!adminId) {
            return res.status(400).json({ message: 'adminId is required.' });
        }

        // Check if the doctor exists
        const adminExists = await Admin.findById(adminId);
        if (!adminExists) {
            return res.status(404).json({ message: 'admin not found.' });
        }
      // Get today's date in 'YYYY-MM-DD' format
      const today = moment().format('YYYY-MM-DD');

      // Find all appointments where app_date is after today
      const upcomingAppointments = await AppointmentBook.find({
          app_date: { $gt: today }
      })
      .select('appointmentType app_date patient_issue diseas_name startTime') // Adjust fields as needed
      .populate('patientId', 'first_name last_name') .populate('doctorId', 'firstName');

      // Check if any upcoming appointments were found
      if (!upcomingAppointments.length) {
          return res.status(404).json({ message: 'No upcoming appointments found.' });
      }

      // Format the startTime to Indian Standard Time (IST) for each appointment
      const formattedAppointments = upcomingAppointments.map(appointment => {
          const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST in 'h:mm A' format
          return {
              ...appointment.toObject(),
              startTime: startTimeIST  // Overwrite startTime with formatted IST time
          };
      });

      // Return the list of upcoming appointments with formatted time
      return res.status(200).json({
          message: 'Upcoming appointments retrieved successfully.',
          appointments: formattedAppointments
      });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'An error occurred while retrieving upcoming appointments.' });
  }
};

const getPreviousAppointments = async (req, res) => {
  try {

        // Get doctorId from request
        const { adminId } = req.query;

        // Validate doctorId
        if (!adminId) {
            return res.status(400).json({ message: 'adminId is required.' });
        }

        // Check if the doctor exists
        const adminExists = await Admin.findById(adminId);
        if (!adminExists) {
            return res.status(404).json({ message: 'admin not found.' });
        }
      // Get today's date in 'YYYY-MM-DD' format
      const today = moment().format('YYYY-MM-DD');

      // Find all appointments where app_date is before today
      const previousAppointments = await AppointmentBook.find({
          app_date: { $lt: today }
      })
      .select('appointmentType app_date patient_issue diseas_name startTime') // Add startTime field
      .populate('patientId', 'first_name last_name').populate('doctorId', 'firstName');

      // Check if any previous appointments were found
      if (!previousAppointments.length) {
          return res.status(404).json({ message: 'No previous appointments found.' });
      }

      // Format startTime to IST
      const formattedAppointments = previousAppointments.map(appointment => ({
          ...appointment._doc,
          startTime: formatToIST(appointment.startTime) // Convert to IST
      }));

      // Return the list of previous appointments
      return res.status(200).json({
          message: 'Previous appointments retrieved successfully.',
          appointments: formattedAppointments
      });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'An error occurred while retrieving previous appointments.' });
  }
};

const getCanceledAppointments = async (req, res) => {
  try {

        // Get doctorId from request
       const { adminId } = req.query;

        // Validate doctorId
        if (!adminId) {
            return res.status(400).json({ message: 'adminId is required.' });
        }

        // Check if the doctor exists
        const adminExists = await Admin.findById(adminId);
        if (!adminExists) {
            return res.status(404).json({ message: 'admin not found.' });
        }

      // Find all appointments where status is 'canceled'
      const canceledAppointments = await AppointmentBook.find({
          status: 0
      })
      .select('appointmentType app_date startTime  patient_issue diseas_name') // Adjust fields as needed
      .populate('doctorId', 'firstName')
      .populate('patientId', 'first_name last_name');
     

      // Check if any canceled appointments were found
      if (!canceledAppointments.length) {
          return res.status(404).json({ message: 'No canceled appointments found.' });
      }

      // Return the list of canceled appointments
      return res.status(200).json({
          message: 'Canceled appointments retrieved successfully.',
          appointments: canceledAppointments
      });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'An error occurred while retrieving canceled appointments.' });
  }
};

const getAppointmentDetailsOfPatientById = async (req, res) => {
  try {
      // Extract appointmentId from the request body
      const { appointmentId } = req.body; // Assuming appointmentId is sent in the body

      // Validate that the appointmentId is provided
      if (!appointmentId) {
          return res.status(400).json({ message: 'Appointment ID is required.' });
      }

      // Find the appointment by appointmentId and populate patient and doctor details
      const appointment = await AppointmentBook.findById(appointmentId)
          .select('patient_issue diseas_name startTime endTime app_date appointmentType') // Select specific fields from appointment
          .populate('patientId', 'first_name last_name phone_number age gender patient_address') // Populate patient details
          .populate('doctorId', 'firstName lastName phone_number'); // Populate doctor details (added lastName and phone_number)

      // Check if the appointment was found
      if (!appointment) {
          return res.status(404).json({ message: 'Appointment not found.' });
      }

      // Ensure populated fields exist
      const { patientId, doctorId } = appointment;
      if (!patientId || !doctorId) {
          return res.status(404).json({ message: 'Patient or Doctor details not found in the appointment.' });
      }

      // Construct the response object with the required fields
      const response = {
          patientFirstName: patientId.first_name,
          patientLastName: patientId.last_name,
          patientIssues: appointment.patient_issue,
          diseaseName: appointment.diseas_name,
          startTime: appointment.startTime,
          endTime: appointment.endTime,
          appointmentDate: appointment.app_date,
          doctorFirstName: doctorId.firstName,
          doctorLastName: doctorId.lastName, // Added doctor last name
          doctorPhoneNumber: doctorId.phone_number, // Added doctor's phone number
          patientPhoneNumber: patientId.phone_number,
          patientAge: patientId.age,
          patientAddress: patientId.patient_address,
          patientGender: patientId.gender,
      };

      // Return the appointment details
      return res.status(200).json({
          message: 'Appointment details retrieved successfully.',
          appointment: response,
      });
  } catch (error) {
      console.error(error);
      return res.status(500).json({ message: 'An error occurred while retrieving appointment details.' });
  }
};

// const getTodayAppointmentsSearch = async (req, res) => {
//   try {
//     const { adminId } = req.body;
//     const { patientName, doctorName } = req.query; // Get patientName and doctorName from query

//     // Validate adminId
//     if (!adminId) {
//       return res.status(400).json({ message: 'adminId is required.' });
//     }

//     // Check if the admin exists
//     const adminExists = await Admin.findById(adminId);
//     if (!adminExists) {
//       return res.status(404).json({ message: 'admin not found.' });
//     }

//     // Get today's date in 'YYYY-MM-DD' format
//     const today = moment().format('YYYY-MM-DD');

//     // Build the search filter based on today's date
//     let searchFilter = { app_date: today }; // Ensure app_date is today's date

//     // If patientName is provided, add it to the search filter
//     if (patientName) {
//       searchFilter['patientId.first_name'] = { $regex: patientName, $options: 'i' }; // Case-insensitive search
//     }

//     // If doctorName is provided, add it to the search filter
//     if (doctorName) {
//       searchFilter['doctorId.firstName'] = { $regex: doctorName, $options: 'i' }; // Case-insensitive search
//     }

//     // Log the search filter for debugging purposes
//     console.log('Search Filter:', searchFilter);

//     // Find today's appointments based on the search filter
//     const todayAppointments = await AppointmentBook.find(searchFilter)
//       .select('appointmentType app_date patient_issue diseas_name startTime') // Adjust fields as needed
//       .populate('patientId', 'first_name last_name')
//       .populate('doctorId', 'firstName');

//     // Check if any appointments were found
//     if (!todayAppointments.length) {
//       return res.status(404).json({ message: 'No appointments found for today matching the search criteria.' });
//     }

//     // Format the startTime to Indian Standard Time (IST) for each appointment
//     const formattedAppointments = todayAppointments.map(appointment => {
//       const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST in 'h:mm A' format
//       return {
//         ...appointment.toObject(),
//         startTime: startTimeIST  // Overwrite startTime with formatted IST time
//       };
//     });

//     // Return the list of today's appointments with the formatted time
//     return res.status(200).json({
//       message: 'Appointments retrieved successfully for today.',
//       appointments: formattedAppointments
//     });

//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({ message: 'An error occurred while retrieving appointments.' });
//   }
// };


// const getUpcomingAppointmentsSearch = async (req, res) => {
//   try {
//     const { adminId } = req.body;
//     const { patientName, doctorName } = req.query; // Get patientName and doctorName from query

//     // Validate adminId
//     if (!adminId) {
//       return res.status(400).json({ message: 'adminId is required.' });
//     }

//     // Check if the admin exists
//     const adminExists = await Admin.findById(adminId);
//     if (!adminExists) {
//       return res.status(404).json({ message: 'Admin not found.' });
//     }

//     // Get today's date in 'YYYY-MM-DD' format
//     const today = moment().format('YYYY-MM-DD');

//     // Build the search filter based on query parameters and app_date
//     let searchFilter = {
//       app_date: { $gt: today }
//     };

//     // If patientName is provided, add it to the search filter
//     if (patientName) {
//       searchFilter['patientId.first_name'] = { $regex: patientName, $options: 'i' }; // Case-insensitive search
//     }

//     // If doctorName is provided, add it to the search filter
//     if (doctorName) {
//       searchFilter['doctorId.firstName'] = { $regex: doctorName, $options: 'i' }; // Case-insensitive search
//     }

//     // Find all upcoming appointments based on the search filter
//     const upcomingAppointments = await AppointmentBook.find(searchFilter)
//       .select('appointmentType app_date patient_issue diseas_name startTime') // Adjust fields as needed
//       .populate('patientId', 'first_name last_name')
//       .populate('doctorId', 'firstName');

//     // Check if any upcoming appointments were found
//     if (!upcomingAppointments.length) {
//       return res.status(404).json({ message: 'No upcoming appointments found.' });
//     }

//     // Format the startTime to Indian Standard Time (IST) for each appointment
//     const formattedAppointments = upcomingAppointments.map(appointment => {
//       const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST in 'h:mm A' format
//       return {
//         ...appointment.toObject(),
//         startTime: startTimeIST  // Overwrite startTime with formatted IST time
//       };
//     });

//     // Return the list of upcoming appointments with formatted time
//     return res.status(200).json({
//       message: 'Upcoming appointments retrieved successfully.',
//       appointments: formattedAppointments
//     });

//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({ message: 'An error occurred while retrieving upcoming appointments.' });
//   }
// };

// const getPreviousAppointmentsSearch = async (req, res) => {
//   try {
//     const { adminId } = req.body;
//     const { patientName, doctorName } = req.query; // Get patientName and doctorName from query

//     // Validate adminId
//     if (!adminId) {
//       return res.status(400).json({ message: 'adminId is required.' });
//     }

//     // Check if the admin exists
//     const adminExists = await Admin.findById(adminId);
//     if (!adminExists) {
//       return res.status(404).json({ message: 'Admin not found.' });
//     }

//     // Get today's date in 'YYYY-MM-DD' format
//     const today = moment().format('YYYY-MM-DD');

//     // Build the search filter based on query parameters and app_date
//     let searchFilter = {
//       app_date: { $lt: today } // Appointments before today
//     };

//     // If patientName is provided, add it to the search filter
//     if (patientName) {
//       searchFilter['patientId.first_name'] = { $regex: patientName, $options: 'i' }; // Case-insensitive search
//     }

//     // If doctorName is provided, add it to the search filter
//     if (doctorName) {
//       searchFilter['doctorId.firstName'] = { $regex: doctorName, $options: 'i' }; // Case-insensitive search
//     }

//     // Find all previous appointments based on the search filter
//     const previousAppointments = await AppointmentBook.find(searchFilter)
//       .select('appointmentType app_date patient_issue diseas_name startTime') // Adjust fields as needed
//       .populate('patientId', 'first_name last_name')
//       .populate('doctorId', 'firstName');

//     // Check if any previous appointments were found
//     if (!previousAppointments.length) {
//       return res.status(404).json({ message: 'No previous appointments found.' });
//     }

//     // Format the startTime to Indian Standard Time (IST) for each appointment
//     const formattedAppointments = previousAppointments.map(appointment => {
//       const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST in 'h:mm A' format
//       return {
//         ...appointment.toObject(),
//         startTime: startTimeIST // Overwrite startTime with formatted IST time
//       };
//     });

//     // Return the list of previous appointments with formatted time
//     return res.status(200).json({
//       message: 'Previous appointments retrieved successfully.',
//       appointments: formattedAppointments
//     });

//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({ message: 'An error occurred while retrieving previous appointments.' });
//   }
// };

// const getCanceledAppointmentsSearch = async (req, res) => {
//   try {
//     const { adminId } = req.body;
//     const { patientName, doctorName } = req.query; // Get patientName and doctorName from query

//     // Validate adminId
//     if (!adminId) {
//       return res.status(400).json({ message: 'adminId is required.' });
//     }

//     // Check if the admin exists
//     const adminExists = await Admin.findById(adminId);
//     if (!adminExists) {
//       return res.status(404).json({ message: 'Admin not found.' });
//     }

//     // Build the search filter for canceled appointments
//     let searchFilter = {
//       status: 0 // Status 0 represents canceled appointments
//     };

//     // If patientName is provided, add it to the search filter
//     if (patientName) {
//       searchFilter['patientId.first_name'] = { $regex: patientName, $options: 'i' }; // Case-insensitive search
//     }

//     // If doctorName is provided, add it to the search filter
//     if (doctorName) {
//       searchFilter['doctorId.firstName'] = { $regex: doctorName, $options: 'i' }; // Case-insensitive search
//     }

//     // Find all canceled appointments based on the search filter
//     const canceledAppointments = await AppointmentBook.find(searchFilter)
//       .select('appointmentType app_date startTime patient_issue diseas_name') // Adjust fields as needed
//       .populate('doctorId', 'firstName')
//       .populate('patientId', 'first_name last_name');

//     // Check if any canceled appointments were found
//     if (!canceledAppointments.length) {
//       return res.status(404).json({ message: 'No canceled appointments found.' });
//     }

//     // Return the list of canceled appointments
//     return res.status(200).json({
//       message: 'Canceled appointments retrieved successfully.',
//       appointments: canceledAppointments
//     });

//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({ message: 'An error occurred while retrieving canceled appointments.' });
//   }
// };


  module.exports = {
    searchDoctorAndPatientist,deleteDoctor,
    allDoctorList,allDoctorListId,searchDoctor,getTodayAppointments,getUpcomingAppointments,getPreviousAppointments,
    getCanceledAppointments,
    getAppointmentDetailsOfPatientById,
    // getTodayAppointmentsSearch,getUpcomingAppointmentsSearch,
    // getPreviousAppointmentsSearch,getCanceledAppointmentsSearch

  }

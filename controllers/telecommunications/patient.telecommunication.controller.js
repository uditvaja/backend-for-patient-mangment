const { formatToIST } = require("../../helpers/timeFormat");
const AppointmentBook = require("../../models/bookAppointment.model");

const moment = require('moment-timezone')

const getTodayAppointmentsForPatient = async (req, res) => {
    try {
        // Find all appointments where telecommunicationStatus is "0"
        const appointments = await AppointmentBook.find({
            telecomunicationStatus: "0"  // Fetch appointments with telecommunicationStatus = "0"
        })
        .select('appointmentType app_date patient_issue startTime endTime') // Select the necessary fields
        .populate('patientId', 'first_name last_name')  // Populate patient's first and last name
        .populate('hospitalId', 'hospital_name')  // Populate hospital name
        .populate('doctorId', 'firstName');  // Populate doctor's first name

        // Check if any appointments were found
        if (!appointments.length) {
            return res.status(404).json({ message: 'No appointments found with telecommunication status "0".' });
        }

        // Format the startTime and endTime to Indian Standard Time (IST) for each appointment
        const formattedAppointments = appointments.map(appointment => {
            const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A');  // Convert to IST
            const endTimeIST = moment(appointment.endTime).tz('Asia/Kolkata').format('h:mm A');  // Convert to IST
            return {
                ...appointment.toObject(),
                startTime: startTimeIST,  // Overwrite startTime with formatted IST time
                endTime: endTimeIST       // Overwrite endTime with formatted IST time
            };
        });

        // Return the list of appointments with telecommunicationStatus "0" and formatted times
        return res.status(200).json({
            message: 'Appointments with telecommunication status "0" retrieved successfully.',
            appointments: formattedAppointments
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'An error occurred while retrieving appointments.' });
    }
};

const getAppointmentsWithinDateRange = async (req, res) => {
    try {
        // Extract fromDate and toDate from the query parameters
        const { fromDate, toDate } = req.query;

        // Validate that both fromDate and toDate are provided
        if (!fromDate || !toDate) {
            return res.status(400).json({ message: 'Both fromDate and toDate are required.' });
        }

        // Parse the fromDate and toDate and check for valid dates
        const startDate = moment(fromDate, 'YYYY-MM-DD', true);
        const endDate = moment(toDate, 'YYYY-MM-DD', true);

        // Validate the parsed dates
        if (!startDate.isValid() || !endDate.isValid()) {
            return res.status(400).json({ message: 'Invalid date format. Please use "YYYY-MM-DD".' });
        }

        // Ensure startDate is not after endDate
        if (startDate.isAfter(endDate)) {
            return res.status(400).json({ message: 'fromDate cannot be after toDate.' });
        }

        // Log for debugging
        console.log("Fetching appointments from", startDate.format('YYYY-MM-DD'), "to", endDate.format('YYYY-MM-DD'));

        // Find all appointments where telecommunicationStatus is "0" and app_date is within the specified range
        const appointments = await AppointmentBook.find({
            telecomunicationStatus: "0",  // Check telecommunicationStatus
            app_date: {
                $gte: startDate.format('YYYY-MM-DD'),  // From date
                $lte: endDate.format('YYYY-MM-DD')     // To date
            }
        })
        .select('appointmentType app_date patient_issue startTime endTime')  // Select necessary fields
        .populate('patientId', 'first_name last_name')  // Populate patient's name
        .populate('hospitalId', 'hospital_name')  // Populate hospital name
        .populate('doctorId', 'firstName');  // Populate doctor's name

        // Check if any appointments were found
        if (!appointments.length) {
            return res.status(404).json({ message: 'No appointments found with telecommunication status "0" in the given date range.' });
        }

        // Format the startTime and endTime to IST (Indian Standard Time)
        const formattedAppointments = appointments.map(appointment => {
            const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A');  // Convert to IST
            const endTimeIST = moment(appointment.endTime).tz('Asia/Kolkata').format('h:mm A');  // Convert to IST
            return {
                ...appointment.toObject(),
                startTime: startTimeIST,  // Overwrite startTime with formatted IST time
                endTime: endTimeIST       // Overwrite endTime with formatted IST time
            };
        });

        // Return the list of appointments
        return res.status(200).json({
            message: 'Appointments with telecommunication status "0" in the specified date range retrieved successfully.',
            appointments: formattedAppointments
        });
    } catch (error) {
        console.error("Error fetching appointments:", error);  // Log any error
        return res.status(500).json({ message: 'An error occurred while retrieving appointments.' });
    }
};

const cancelAppointment = async (req, res) => {
    try {
        const { appointmentId } = req.body; // Get appointmentId from request body

        // Validate appointmentId
        if (!appointmentId) {
            return res.status(400).json({ message: 'Appointment ID is required.' });
        }

        // Find the appointment by appointmentId
        const appointment = await AppointmentBook.findById(appointmentId);

        // Check if appointment exists
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found.' });
        }

        // Update the telecommunicationStatus to "1" (canceled)
        appointment.telecomunicationStatus = "1";  // Update status to canceled

        // Mark the appointment as canceled (if you want to remove from scheduling but not delete from the DB)
        appointment.isCanceled = true; // Assuming you have an 'isCanceled' flag

        // Save the updated appointment
        await appointment.save();

        // Return success response
        return res.status(200).json({ 
            message: 'Appointment canceled successfully.',
            appointmentId: appointment._id,
            status: 'canceled'
        });
    } catch (error) {
        console.error('Error canceling appointment:', error);
        return res.status(500).json({ message: 'An error occurred while canceling the appointment.' });
    }
};


const getUpcomingAppointmentsForPatient = async (req, res) => {
    try {
        // Extract fromDate and toDate from the request body
        let { fromDate, toDate } = req.body; // Assuming dates are sent in the request body

        // Set default values if fromDate or toDate are not provided
        const today = moment().format('YYYY-MM-DD');
        fromDate = fromDate ? moment(fromDate).format('YYYY-MM-DD') : today; // Default to today
        toDate = toDate ? moment(toDate).format('YYYY-MM-DD') : moment().add(1, 'year').format('YYYY-MM-DD'); // Default to 1 year from now

        // Ensure fromDate is not after toDate
        if (moment(fromDate).isAfter(toDate)) {
            return res.status(400).json({ message: 'fromDate cannot be after toDate.' });
        }

        // Find all appointments where app_date is between fromDate and toDate
        const upcomingAppointments = await AppointmentBook.find({
            app_date: { $gte: fromDate, $lte: toDate }
        })
        .select('appointmentType app_date patient_issue diseas_name startTime endTime') // Select fields as needed
        .populate('patientId', 'first_name last_name');

        // Check if any upcoming appointments were found
        if (!upcomingAppointments.length) {
            return res.status(404).json({ message: 'No appointments found in the provided date range.' });
        }

        // Format the startTime and endTime to Indian Standard Time (IST) for each appointment
        const formattedAppointments = upcomingAppointments.map(appointment => {
            const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST
            const endTimeIST = moment(appointment.endTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST
            return {
                ...appointment.toObject(),
                startTime: startTimeIST,  // Overwrite startTime with formatted IST time
                endTime: endTimeIST       // Overwrite endTime with formatted IST time
            };
        });

        // Return the list of appointments within the date range with formatted times
        return res.status(200).json({
            message: 'Appointments retrieved successfully.',
            appointments: formattedAppointments
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'An error occurred while retrieving appointments.' });
    }
};

const getUpcomingAppointmentsSearchForPatient = async (req, res) => {
    try {
        // Extract fromDate, toDate, and patientName from the request body
        let { fromDate, toDate, patientName } = req.body; // Assuming dates and patient name are sent in the request body

        // Set default values if fromDate or toDate are not provided
        const today = moment().format('YYYY-MM-DD');
        fromDate = fromDate ? moment(fromDate).format('YYYY-MM-DD') : today; // Default to today
        toDate = toDate ? moment(toDate).format('YYYY-MM-DD') : moment().add(1, 'year').format('YYYY-MM-DD'); // Default to 1 year from now

        // Ensure fromDate is not after toDate
        if (moment(fromDate).isAfter(toDate)) {
            return res.status(400).json({ message: 'fromDate cannot be after toDate.' });
        }

        // Build the query for appointments
        let appointmentQuery = {
            app_date: { $gte: fromDate, $lte: toDate }
        };

        // Add patient name filtering if provided
        let patientQuery = {};
        if (patientName) {
            // Use case-insensitive search for first_name
            patientQuery = { first_name: { $regex: new RegExp(patientName, 'i') } };
        }

        // Find all appointments where app_date is between fromDate and toDate and optionally filter by patient first_name
        const upcomingAppointments = await AppointmentBook.find(appointmentQuery)
            .select('appointmentType app_date patient_issue diseas_name startTime endTime') // Select fields as needed
            .populate({
                path: 'patientId',
                match: patientQuery, // Apply the patient name filter here
                select: 'first_name last_name' // Select the fields to populate
            });

        // Filter out appointments where the patient does not match the search criteria (null patientId due to match)
        const filteredAppointments = upcomingAppointments.filter(appointment => appointment.patientId);

        // Check if any upcoming appointments were found
        if (!filteredAppointments.length) {
            return res.status(404).json({ message: 'No appointments found in the provided date range or patient name.' });
        }

        // Format the startTime and endTime to Indian Standard Time (IST) for each appointment
        const formattedAppointments = filteredAppointments.map(appointment => {
            const startTimeIST = moment(appointment.startTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST
            const endTimeIST = moment(appointment.endTime).tz('Asia/Kolkata').format('h:mm A'); // Convert to IST
            return {
                ...appointment.toObject(),
                startTime: startTimeIST,  // Overwrite startTime with formatted IST time
                endTime: endTimeIST       // Overwrite endTime with formatted IST time
            };
        });

        // Return the list of appointments with formatted times
        return res.status(200).json({
            message: 'Appointments retrieved successfully.',
            appointments: formattedAppointments
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'An error occurred while retrieving appointments.' });
    }
};

const getPreviousAppointmentsForPatient = async (req, res) => {
    try {
        // Get today's date in 'YYYY-MM-DD' format
        const today = moment().format('YYYY-MM-DD');

        // Find all appointments where app_date is before today
        const previousAppointments = await AppointmentBook.find({
            app_date: { $lt: today }
        })
        .select('appointmentType app_date patient_issue diseas_name startTime') // Add startTime field
        .populate('patientId', 'first_name last_name');

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

const getPreviousAppointmentsSearchForPatient = async (req, res) => {
    try {
        // Get today's date in 'YYYY-MM-DD' format
        const today = moment().format('YYYY-MM-DD');

        // Extract patientName from the request body (or query params)
        const { patientName } = req.body; // Assuming the patient name is sent in the request body

        // Find all appointments where app_date is before today
        const previousAppointments = await AppointmentBook.find({
            app_date: { $lt: today }
        })
        .select('appointmentType app_date patient_issue diseas_name startTime') // Add startTime field
        .populate({
            path: 'patientId',
            match: patientName ? { first_name: { $regex: new RegExp(patientName, 'i') } } : {}, // Case-insensitive search for first_name
            select: 'first_name last_name'
        });

        // Filter out appointments where the patient does not match the search criteria (due to null match from populate)
        const filteredAppointments = previousAppointments.filter(appointment => appointment.patientId);

        // Check if any previous appointments were found
        if (!filteredAppointments.length) {
            return res.status(404).json({ message: 'No previous appointments found.' });
        }

        // Format startTime to IST
        const formattedAppointments = filteredAppointments.map(appointment => ({
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

const getCanceledAppointmentsForPatient = async (req, res) => {
    try {
        // Find all appointments where status is 'canceled'
        const canceledAppointments = await AppointmentBook.find({
            status: 0
        })
        .select('appointmentType app_date startTime  patient_issue diseas_name') // Adjust fields as needed
        // .populate('doctorId', 'firstName')
        .populate('patientId', 'first_name last_name')
       

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

const getCanceledAppointmentsSearchForPatient = async (req, res) => {
    try {
        // Extract the search parameter from the request query or body
        const { first_name } = req.query; // Assuming you are passing 'first_name' as a query parameter

        // Build the query for canceled appointments
        const query = { status: 0 }; // Status '0' indicates canceled

        // Modify the query if a search parameter is provided
        if (first_name) {
            query['patientId.first_name'] = { $regex: first_name, $options: 'i' }; // Case-insensitive search
        }

        // Find all canceled appointments
        const canceledAppointments = await AppointmentBook.find(query)
            .select('appointmentType app_date startTime patient_issue diseas_name') // Adjust fields as needed
            .populate({
                path: 'patientId',
                match: { first_name: { $regex: first_name || '', $options: 'i' } }, // Search by first_name
                select: 'first_name last_name'
            });

        // Filter out appointments that do not match the patient search (in case of null matches)
        const filteredAppointments = canceledAppointments.filter(appointment => appointment.patientId);

        // Check if any canceled appointments were found
        if (!filteredAppointments.length) {
            return res.status(404).json({ message: 'No canceled appointments found.' });
        }

        // Return the list of canceled appointments
        return res.status(200).json({
            message: 'Canceled appointments retrieved successfully.',
            appointments: filteredAppointments
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'An error occurred while retrieving canceled appointments.' });
    }
};

const updateJoinCallForPatient = async (req, res) => {
    try {
        // Extract appointmentId from the request parameters
        const { appointmentId } = req.body;

        // Validate that the appointmentId is provided
        if (!appointmentId) {
            return res.status(400).json({ message: 'Appointment ID is required.' });
        }

        // Find the appointment by appointmentId and update the join_call status to 0
        const updatedAppointment = await AppointmentBook.findByIdAndUpdate(
            appointmentId,
            { join_call: 0 }, // Set join_call to 0
            { new: true, runValidators: true } // Return the updated document and run validators
        );

        // Check if the appointment was found and updated
        if (!updatedAppointment) {
            return res.status(404).json({ message: 'Appointment not found.' });
        }

        // Return the updated appointment details
        return res.status(200).json({
            message: 'Join call status updated successfully.',
            appointment: updatedAppointment
        });
    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: 'An error occurred while updating the join call status.' });
    }
};

const getAppointmentDetailsByIdForPatient = async (req, res) => {
    try {
        // Extract appointmentId from the request body
        const { appointmentId } = req.body; // Assuming appointmentId is sent in the body

        // Validate that the appointmentId is provided
        if (!appointmentId) {
            return res.status(400).json({ message: 'Appointment ID is required.' });
        }

        // Find the appointment by appointmentId and populate patient details
        const appointment = await AppointmentBook.findById(appointmentId)
            .select('patient_issue diseas_name startTime endTime') // Select specific fields
            .populate('patientId', 'first_name last_name'); // Populate patient details

        // Check if the appointment was found
        if (!appointment) {
            return res.status(404).json({ message: 'Appointment not found.' });
        }

        // Construct the response object with the required fields
        const response = {
            patientFirstName: appointment.patientId.first_name,
            patientLastName: appointment.patientId.last_name,
            patientIssues: appointment.patient_issue,
            diseaseName: appointment.diseas_name,
            startTime: appointment.startTime,
            endTime: appointment.endTime,
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

const getAppointmentDetailsOfPatientByIdForPatient = async (req, res) => {
    try {
        // Extract appointmentId from the request body
        const { appointmentId } = req.body; // Assuming appointmentId is sent in the body

        // Validate that the appointmentId is provided
        if (!appointmentId) {
            return res.status(400).json({ message: 'Appointment ID is required.' });
        }

        // Find the appointment by appointmentId and populate patient and doctor details
        const appointment = await AppointmentBook.findById(appointmentId)
            .select('patient_issue diseas_name startTime endTime app_date') // Select specific fields from appointment
            .populate('patientId', 'first_name last_name phone_number age gender patient_address') // Populate patient details
            .populate('doctorId', 'firstName lastName phone_number'); // Populate doctor details

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
            patientFirstName: patientId.first_name || 'N/A', // Fallback if undefined
            patientLastName: patientId.last_name || 'N/A',   // Fallback if undefined
            patientIssues: appointment.patient_issue || 'N/A', // Fallback if undefined
            diseaseName: appointment.diseas_name || 'N/A',     // Fallback if undefined
            startTime: appointment.startTime || 'N/A',         // Fallback if undefined
            endTime: appointment.endTime || 'N/A',             // Fallback if undefined
            appointmentDate: appointment.app_date || 'N/A',    // Fallback if undefined
            doctorFirstName: doctorId.firstName || 'N/A',      // Fallback if undefined
            doctorLastName: doctorId.lastName || 'N/A',        // Fallback if undefined
            doctorPhoneNumber: doctorId.phone_number || 'N/A',  // Fallback if undefined
            patientPhoneNumber: patientId.phone_number || 'N/A', // Fallback if undefined
            patientAge: patientId.age || 'N/A',                // Fallback if undefined
            patientAddress: patientId.patient_address || 'N/A', // Fallback if undefined
            patientGender: patientId.gender || 'N/A',          // Fallback if undefined
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


module.exports = {
    getTodayAppointmentsForPatient,
    getUpcomingAppointmentsForPatient,
    getUpcomingAppointmentsSearchForPatient,
    getPreviousAppointmentsForPatient,
    getPreviousAppointmentsSearchForPatient,
    getCanceledAppointmentsForPatient,
    getCanceledAppointmentsSearchForPatient,
    updateJoinCallForPatient,
    getAppointmentDetailsByIdForPatient,
    getAppointmentDetailsOfPatientByIdForPatient,getAppointmentsWithinDateRange,
    cancelAppointment
};

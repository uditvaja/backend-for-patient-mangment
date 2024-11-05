// const mongoose = require("mongoose");
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const Bill = require("../../models/bill.model");

/* ------------------------------- CREATE Hospital  ------------------------------- */
const moment = require('moment');
const Hospital = require("../../models/hospital.model");

const createBill = async (req, res) => {
  try {
    const reqBody = req.body;

    // Convert BillTime to correct format if it's a string
    if (typeof reqBody.BillTime === 'string') {
      reqBody.BillTime = moment(reqBody.BillTime, 'hh:mm A').toDate(); // Convert "12:19 Pm" to Date
    }

    const bill = await Bill.create(reqBody);
    if (!bill) {
      throw new Error("Failed to create bill");
    }
    res.status(200).json({
      status: 200,
      message: "Successfully created a new bill",
      success: true,
      data: bill,
    });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

const monitorBill = async (req, res) => {
    try {
      // Retrieve specific fields from all bills in the database
      const bills = await Bill.find({}, 'BillNumber disease_name patient_name phoneNumber BillDate BillTime is_active'); // Add fields you want to retrieve
  
      // Check if any bills exist
      if (bills.length === 0) {
        return res.status(404).json({
          success: false,
          message: "No bills found",
        });
      }
  
      // Map bills to include status based on is_active field
      const formattedBills = bills.map(bill => ({
        BillNumber: bill.BillNumber,
        disease_name: bill.disease_name,
        patient_name: bill.patient_name,
        phoneNumber: bill.phoneNumber,
        BillDate: bill.BillDate,
        BillTime: bill.BillTime,
        status: bill.is_active ? 'Paid' : 'Unpaid' // Determine status based on is_active field
      }));
  
      // Return the list of formatted bills
      res.status(200).json({
        success: true,
        message: "Retrieved all bills successfully",
        data: formattedBills,
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: "An error occurred while retrieving bills: " + error.message,
      });
    }
  };

  const searchPatient = async (req, res) => {
    try {
      const { query } = req.query;
  
      // Check if query parameter is provided
      if (!query) {
        return res.status(400).json({
          status: 400,
          success: false,
          message: "Query parameter is missing.",
        });
      }
  
      // Use a regular expression for case-insensitive search
      const regex = new RegExp(query, "i");
  
      // Prepare search criteria
      const searchCriteria = {
        $or: [
          { patient_name: regex },    // Search by patient name
          { disease_name: regex },     // Optional: search by disease name
        ]
      };
  
      // Check if the query is a number for phone number search
      if (!isNaN(query)) {
        // If the query is a valid number, convert it to Number type for searching
        searchCriteria.$or.push({ phoneNumber: Number(query) }); // Add phoneNumber search
      }
  
      // Search in the Bill model
      const patientResults = await Bill.find(searchCriteria);
  
      if (patientResults.length === 0) {
        return res.status(404).json({
          status: 404,
          success: false,
          message: "No matching patients found for the given query.",
        });
      }
  
      // If results are found, return a success response with the search results
      res.status(200).json({
        status: 200,
        success: true,
        message: "Search data retrieved successfully.",
        searchResults: patientResults.map(bill => ({
          BillNumber: bill.BillNumber,
          patient_name: bill.patient_name,
          disease_name: bill.disease_name,
          phoneNumber: bill.phoneNumber,
          BillDate: bill.BillDate,
          BillTime: bill.BillTime,
          status: bill.is_active ? 'Active' : 'Inactive', // Include status based on is_active field
        })),
      });
    } catch (error) {
      console.error("Error in searchPatient:", error);
      res.status(500).json({
        status: 500,
        success: false,
        message: "Internal Server Error",
      });
    }
  };


// Update Bill Fields
// const updateBill = async (billId, updateData) => {
//   try {
//     const updatedBill = await Bill.findByIdAndUpdate(billId, updateData, { new: true });
//     console.log('Bill updated:', updatedBill);
//   } catch (error) {
//     console.error('Error updating bill:', error);
//   }
// };

// // Update Hospital Fields
// const updateHospital = async (hospitalId, updateData) => {
//   try {
//     const updatedHospital = await Hospital.findByIdAndUpdate(hospitalId, updateData, { new: true });
//     console.log('Hospital updated:', updatedHospital);
//   } catch (error) {
//     console.error('Error updating hospital:', error);
//   }
// };

// const updateHospitalLogo = async (hospitalId, imagePath) => {
//   try {
//     // Upload to Cloudinary
//     const result = await cloudinary.uploader.upload(imagePath, {
//       folder: 'hospital_logos',
//     });

//     // Update Hospital document with the new logo details
//     const updatedHospital = await Hospital.findByIdAndUpdate(hospitalId, {
//       'hospital_logo.public_id': result.public_id,
//       'hospital_logo.url': result.secure_url,
//     }, { new: true });

//     console.log('Hospital logo updated:', updatedHospital);
//   } catch (error) {
//     console.error('Error updating hospital logo:', error);
//   }
// };




const billView = async (req, res) => {
  try {
    const bills = await Bill.find(); // Fetch all records from the Bill collection
    res.status(200).json(bills); // Send the bills data as a JSON response
  } catch (error) {
    res.status(500).json({ error: 'An error occurred while fetching bills' });
  }
};

  // const updateDocProfile = async (req, res) => {
  //   try {
  //     const reqbody = req.body;
  
  //     // If there's a file uploaded, remove any existing image first
  //     if (req.file) {
  //       const user = await Bill.findById(reqbody.doctorId);
  //       if(!user){
  //         return res.status(401).json({status:401,success:false, message: "Doctor not found!"})
  //       }
  //       if (user && user.image) {
  //         const imagePath = path.join(__dirname, "/../../../public/doctorImg", user.image);
  //         if (fs.existsSync(imagePath)) {
  //           fs.unlinkSync(imagePath);
  //         } 
  //       }
  //       reqbody.image = req.file.filename;
  //     }
  
  //     const user = await Doctor.findById(reqbody.doctorId);
  
  //     if (!user) {
  //       throw new Error(` doctorId ${reqbody.doctorId} not found`);
  //     }
  //     // Concatenate first name and last name
  //     const fullName = reqbody.first_name + " " + reqbody.last_name;
  //     reqbody.name = fullName;
  
  //     // Update user data in the database
  //     const isUpdate = await Doctor.findByIdAndUpdate(
  //       reqbody.doctorId,
  //       {
  //         $set: reqbody,
  //       },
  //       { new: true }
  //     );
  //     res.status(200).json({
  //       status: 200,
  //       success: true,
  //       updateData: isUpdate,
  //       message: "Update profile successfully",
  //     });
  //   } catch (err) {
  //     res.status(400).json({ success: false, error: err.message });
  //   }
  // };

  // updateHospitalAndBill = async (req, res) => {
  //   try {
  //     const { hospitalId, billId } = req.body; // Keep this
  
  //     // Initialize an empty object for storing updates
  //     let updateData = {};
  
  //     // Check if the hospital exists
  //     const hospital = await Hospital.findById(hospitalId);
  //     if (!hospital) {
  //       return res.status(404).json({ success: false, message: "Hospital not found!" });
  //     }
  
  //     // Check if the bill exists
  //     const billExists = await Bill.findById(billId); // Use the Bill model
  //     if (!billExists) {
  //       return res.status(404).json({ success: false, message: "Bill not found!" });
  //     }
  
  //     // Check if there is a new file uploaded (hospital logo)
  //     if (req.file) {
  //       // If the hospital already has an image, delete it from Cloudinary
  //       if (hospital.hospital_logo && hospital.hospital_logo.public_id) {
  //         await cloudinary.uploader.destroy(hospital.hospital_logo.public_id);
  //       }
  
  //       // Upload the new image to Cloudinary
  //       const uploadResponse = await cloudinary.uploader.upload(req.file.path, {
  //         folder: 'hospital_images', // Optional folder to organize images on Cloudinary
  //         resource_type: 'image',   // Ensure the resource type is set to 'image'
  //       });
  
  //       // Update image field in updateData
  //       updateData.hospital_logo = {
  //         public_id: uploadResponse.public_id,
  //         url: uploadResponse.secure_url,
  //       };
  //     }
  
  //     // Add other fields from req.body.hospital to updateData
  //     if (req.body.hospital) {
  //       for (let key in req.body.hospital) {
  //         if (req.body.hospital[key]) {
  //           updateData[key] = req.body.hospital[key];
  //         }
  //       }
  //     }
  
  //     // Update the hospital with the new data
  //     const hospitalUpdate = await Hospital.findByIdAndUpdate(
  //       hospitalId,
  //       { $set: updateData }, // Set the updated fields, including the image
  //       { new: true } // Return the updated document
  //     );
  
  //     // Update the bill fields from req.body.bill
  //     const billUpdateData = req.body.bill || {}; // Ensure there's an object for bill updates
  //     const bill = await Bill.findByIdAndUpdate(
  //       billId,
  //       { $set: billUpdateData }, // Update the bill fields
  //       { new: true }
  //     );
  
  //     // Respond with success and updated documents
  //     res.status(200).json({
  //       success: true,
  //       message: "Hospital and bill details updated successfully!",
  //       hospitalUpdate,
  //       bill,
  //     });
  
  //     // Optional: Remove the file from the server after upload
  //     if (req.file && req.file.path) {
  //       fs.unlinkSync(req.file.path); // Delete the file from local storage
  //     }
  
  //   } catch (error) {
  //     console.error('Error updating hospital and bill:', error.message);
  //     res.status(500).json({
  //       success: false,
  //       message: "An error occurred: " + error.message,
  //     });
  //   }
  // };
  
module.exports = {
    createBill,
    monitorBill,
    searchPatient,billView
    
    // updateBill,updateHospital,updateHospitalLogo
    // updateHospitalAndBill
  };

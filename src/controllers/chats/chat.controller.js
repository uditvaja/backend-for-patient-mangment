const Chat = require('../../models/chat.model');
const cloudinary = require('cloudinary').v2;

const mongoose = require('mongoose')

// Fetch all chat messages between a specific patient and doctor
// exports.getAllMessages = async (req, res) => {
//   const { patientId, doctorId } = req.query;

//   try {
//     const messages = await Chat.find({
//       $or: [
//         { patientId, doctorId },
//         { patientId: doctorId, doctorId: patientId }
//       ]
//     }).sort({ timestamp: 1 });

//     res.json(messages);
//   } catch (error) {
//     res.status(500).json({ error: 'Failed to fetch messages' });
//   }
// };

// // Save a new message
// exports.saveMessage = async (data) => {
//   try {
//     const chatMessage = new Chat({
//       message: data.message,
//       patientId: data.patientId,
//       doctorId: data.doctorId,
//       senderId: data.senderId
//     });
//     await chatMessage.save();
//   } catch (error) {
//     console.error('Failed to save message:', error);
//   }
// };

// FOR  API 
// Save a new message
exports.saveMessage = async (req, res) => {
  console.log('Request body:', req.body); // Log incoming data
  const data = req.body;

  try {
    const chatMessage = new Chat({
      message: data.message,
      patientId: data.patientId,
      doctorId: data.doctorId,
      senderId: data.senderId
    });
    await chatMessage.save();
    res.status(200).json({ message: 'Message saved successfully' });
  } catch (error) {
    console.error('Failed to save message:', error);
    res.status(500).json({ error: 'Failed to save message' });
  }
};

// Fetch all messages
exports.getAllMessages = async (req, res) => {
  const { patientId, doctorId } = req.query;
  console.log('Fetching messages for:', patientId, doctorId); // Log query params

  try {
    const messages = await Chat.find({
      $or: [
        { patientId, doctorId },
        { patientId: doctorId, doctorId: patientId }
      ]
    }).sort({ timestamp: 1 });

    res.status(200).json(messages);
  } catch (error) {
    console.error('Failed to fetch messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
};
exports. updateimageSenderId = async (req, res) => {
  try {
    const { chatId } = req.body;

    // Validate required fields
    if (!chatId) {
      return res.status(400).json({
        status: 400,
        success: false,
        message: 'chatId is a required field!',
      });
    }

    // Fetch the admin's current profile
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({
        status: 404,
        success: false,
        message: 'chat not found!',
      });
    }

    // Initialize an empty object for storing updates
    let updateData = {};

    // Check if there is a new file uploaded
    if (req.file) {
      console.log('Uploaded file:', req.file);
      
      // If there's an existing image, delete it from Cloudinary
      if (chat.image && chat.image.public_id) {
        await cloudinary.uploader.destroy(chat.image.public_id);
      }

      // Upload the new image to Cloudinary
      const uploadResponse = await cloudinary.uploader.upload(req.file.path);
      // console.log('uploadResponse:', uploadResponse);

      // Update image field in updateData
      updateData.image = {
        public_id: uploadResponse.public_id,
        url: uploadResponse.secure_url,
      };
      console.log('Updated image data:line number-121 chat update', updateData.image);
    }

    // Add other fields from req.body to updateData
    for (let key in req.body) {
      if (req.body[key]) {
        updateData[key] = req.body[key];
      }
    }

    // Update the admin profile with new image and other fields
    const updatedPatient = await Chat.findByIdAndUpdate(chatId, { $set: updateData }, { new: true });

    // Return the updated admin profile
    return res.status(200).json({
      status: 200,
      success: true,
      updateData: updatedPatient,
      message: "Profile updated successfully",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: err.message });
  }
};
exports.updatepdfSenderId = async (req, res) => {
  try {
    const { chatId } = req.body;

    // Validate required fields
    if (!chatId) {
      return res.status(400).json({
        status: 400,
        success: false,
        message: 'chatId is a required field!',
      });
    }

    // Fetch the chat's current record
    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({
        status: 404,
        success: false,
        message: 'chat not found!',
      });
    }

    // Initialize an empty object for storing updates
    let updateData = {};

    // Check if there is a new file uploaded (PDF)
    if (req.file) {
      console.log('Uploaded file:', req.file);

      // If there's an existing PDF, delete it from Cloudinary
      if (chat.pdf && chat.pdf.public_id) {
        await cloudinary.uploader.destroy(chat.pdf.public_id, { resource_type: "raw" });
      }

      // Upload the new PDF to Cloudinary with resource_type as "raw"
      const uploadResponse = await cloudinary.uploader.upload(req.file.path, {
        resource_type: "raw", // This ensures Cloudinary knows it's not an image, but a PDF or other file type
      });

      // Update the PDF field in updateData
      updateData.pdf = {
        public_id: uploadResponse.public_id,
        url: uploadResponse.secure_url,
      };
      console.log('Updated PDF data:', updateData.pdf);
    }

    // Add other fields from req.body to updateData
    for (let key in req.body) {
      if (req.body[key]) {
        updateData[key] = req.body[key];
      }
    }

    // Update the chat record with the new PDF and other fields
    const updatedChat = await Chat.findByIdAndUpdate(chatId, { $set: updateData }, { new: true });

    // Return the updated chat record
    return res.status(200).json({
      status: 200,
      success: true,
      updateData: updatedChat,
      message: "Profile updated successfully",
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, error: err.message });
  }
};
// exports.getLatestMessages = async (req, res) => {
//   const { patientId, doctorId } = req.query;

//   try {
//     const latestMessages = await Chat.aggregate([
//       {
//         $match: {
//           $or: [
//             { patientId: new mongoose.Types.ObjectId(patientId), doctorId: new mongoose.Types.ObjectId(doctorId) },
//             { patientId: new mongoose.Types.ObjectId(doctorId), doctorId: new mongoose.Types.ObjectId(patientId) }
//           ]
//         }
//       },
//       {
//         $sort: { timestamp: -1 }
//       },
//       {
//         $group: {
//           _id: { patientId: "$patientId", doctorId: "$doctorId" },
//           latestMessage: { $first: "$$ROOT" }
//         }
//       }
//     ]);

//     res.status(200).json(latestMessages.map(group => group.latestMessage));
//   } catch (error) {
//     console.error('Failed to fetch latest messages:', error);
//     res.status(500).json({ error: 'Failed to fetch latest messages' });
//   }
// };


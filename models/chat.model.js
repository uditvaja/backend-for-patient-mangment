  const mongoose = require('mongoose');

  const chatSchema = new mongoose.Schema({
    message: { type: String },
    patientId: {   type: mongoose.Schema.Types.ObjectId,
      ref: 'patient',  },  // Store the ID of the patient
    doctorId: {  type: mongoose.Schema.Types.ObjectId,
      ref: 'doctor',
  },    // Store the ID of the doctor
  senderId: { type: mongoose.Schema.Types.ObjectId,},
    timestamp: { type: Date, default: Date.now },
    image: {
      public_id: String,
      url: String,
    },
    pdf: {  // Add a field to store PDF information
      public_id: String,
      url: String,
    },
  });

  const Chat = mongoose.model('Chat', chatSchema);
  module.exports = Chat;

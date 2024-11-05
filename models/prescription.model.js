const mongoose = require('mongoose');

const prescriptionSchema = new mongoose.Schema({
  patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'patient',
  },
  doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'doctor',
  },
  mdecinename: {
    type: Array,
  },
  strength: {
    type: Array,
  },
  dose: {
    type: Array,
  },
  duration: {
    type: Array,
  },
  when_to_take: {
    type: Array,
  },
  appointmentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'appointmentBook',
  },
  additional_notes: {
    type: String,
  },
  image: {
    public_id: { type: String },
    url: { type: String },
  },
  description: {
    type: String,
  },
  date: {
    type: Date,
    default: Date.now, // Automatically sets the current date
  },
  totalPrice: { type: Number, required: true },
  insuranceCompany: { type: String },
  insurancePlan: { type: String },
  claimAmount: { type: Number },
  claimedAmount: { type: Number },
  quantity: {
    type: Number,
    min: 1, // Quantity should be at least 1
  },
  medicinePrices: { // New field to store the prices of medicines
    type: [Object],
    required: true, // Ensure this is always provided
  }
});

const Prescription = mongoose.model('prescription', prescriptionSchema);
module.exports = Prescription;

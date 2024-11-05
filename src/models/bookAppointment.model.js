const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
patientId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'patient',  // Reference to the Patient model
},
add_notes:{
   type:String,
},
doctorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'doctor',  // Reference to the Patient model
},

// doctorTimeSlot:{
//    type: mongoose.Schema.Types.ObjectId,
//    ref: 'doctimeslot',  // Reference to the Patient model
// },
hospitalId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'hospital',  // Reference to the Patient model
},
patient_issue:{
type:String,
},
diseas_name:{
    type:String,
},
appointmentType:{
    type:String,
},

country:{
   type:String,
},
state:{
   type:String,
},
city:{
   type:String,
},

 app_date: {
    type: Date,
 },
 app_time:{
    type:String,
 },
 amount: {
    type: String,
    // required: [true, "Amount is required."],
  },
  specialist:{
type:String,
  },
//   1-cancel,0-update when bookappointment,
  status: { 
    type: Number,
    default: 0, //0-Pending,1-Completed,2-Cancelled,3-Accepted
  },
  startTime: Date, // Storing start time as Date
  endTime: Date,   // Storing end time as Date
  cancel_appointment: {
    type: String,
  },

 join_call:{
type:String,
default:"",
 },
 cancel_date: { type: String }, // To store cancellation date
    cancel_time: { type: String },
   // ,0-schedule,1-previous,2-cancel,3-pending
telecomunicationStatus:{type:String,default:"0"},
});

const AppointmentBook = mongoose.model('appointmentBook', bookSchema);
module.exports = AppointmentBook;
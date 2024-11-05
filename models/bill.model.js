const mongoose = require('mongoose');

const billSchema = new mongoose.Schema({
 patient_name:{
    type:String,
 },
 doctor_name:{
    type:String,
 },
 desription:{
type:String,
 },
 payment_type:{
    type:String,
},

 patient_adress:{
   type:String,
 },
 phoneNumber:{
   type:Number, 
 },
 gender:{
   type:String,
 },
 age:{
  type:String,
 },
 disease_name:{
   type:String    
 },
 status:{
    type:String,
    default:"unpaid",
 },
 is_active:{
    type:Boolean,
    default:false,
 },
 BillDate:{
    type:Date,
 },
 BillTime:{
    type:String,
 },
 BillNumber:{
    type:Number,
 },
 discount:{
    type:Number,
 },
 tax:{
    type:String,
 },
 amount:{
    type:Number,
 },
 TotalAmount:{
    type:Number,
 },
 insuranceCompany:{
    type:String,
 },
 insurancePlan:{
    type:String,
 },
 claimAmount:{
    type:Number,
 },
 claimedAmount:{
    type:Number,
 },
});

const Bill = mongoose.model('bill', billSchema);
module.exports = Bill;
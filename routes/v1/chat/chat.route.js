const express = require('express');
const router = express.Router();
const ChatController = require('../../../src/controllers/chats/chat.controller');
const multer = require('multer');
const authenticDoctor = require("../../../middlewares/doctorAuth");
const { singleFileUpload,singleFileUploadPdf } = require('../../../src/helpers/upload');

// Fetch all messages
router.post('/get-all', ChatController.saveMessage);

router.get('/get-all-sms', ChatController.getAllMessages);

// router.get('/get-all-sms-latest', ChatController.getLatestMessages);




// Using memoryStorage for in-memory file storage
// const storage = multer.memoryStorage(); 

// // Function to handle single file uploads (in this case, image)
// const upload = multer({ storage: storage });

// module.exports = upload;

router.put(
  '/update-image',  
  // authenticDoctor,
  singleFileUpload('/chatImg', 'image'),
  ChatController.updateimageSenderId // Controller function to handle the update
);

router.put(
  '/update-image-pdf',  
  // authenticDoctor,
  singleFileUploadPdf('/chatImg', 'pdf'),
  ChatController.updatepdfSenderId // Controller function to handle the update
);

module.exports = router;
const http = require("http");
const express = require("express");
const bodyParser = require("body-parser");
const { connectDB } = require("./db/dbConnection"); 
const config = require("./config/config");
const cors = require("cors");
const routes = require("./routes/v1");
const path = require("path");
const errorHandler = require("./helpers/error");
// const Chat = require('./');
const socketIO = require("socket.io");
// const chatController = require('./src/controllers/chats/chat.controller');

const app = express();
const server = http.createServer(app);

// Attach socket.io to the server
const io = socketIO(server, {
  cors: {
    origin: "*", 
    methods: ["GET", "POST"]
  }
});

// Middlewaresapp.use(express.json());
app.use(express.json());

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.resolve(__dirname, `./public`)));
app.use("/v1", routes);
app.use("/public/adminImg", express.static(path.join(__dirname, "./public/adminImg")));

// Error handler middleware
app.use(errorHandler);


connectDB();

// // Socket.IO connection event handler
// io.on('connection', (socket) => {
//   console.log('New user connected:', socket.id);

//   // Listen for the 'send_message' event
//   socket.on('send_message', async (data) => {
//     // Emit the message to everyone (including sender and receiver)
//     io.emit('receive_message', data); // Broadcast to both patient and doctor

//     // Save the message in the database
//     await chatController.saveMessage(data);
//   });

//   // Handle disconnection
//   socket.on('disconnect', () => {
//     console.log('User disconnected:', socket.id);
//   });
// });
app.get('/',(req,res)=>{
  res.json("hello worldfhrfh")
  })

// Start the server
server.listen(config.port, () => {
  console.log("Server listening on port " + config.port);
});

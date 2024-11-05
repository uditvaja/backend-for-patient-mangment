// socket.js
const socketIO = require('socket.io');

let io;

// Initialize the Socket.IO server
module.exports = {
  init: (httpServer) => {
    io = socketIO(httpServer, {
      cors: {
        origin: "*",  // Allow requests from all origins (adjust as needed)
        methods: ["GET", "POST"]
      }
    });
    return io;
  },
  getIO: () => {
    if (!io) {
      throw new Error('Socket.io not initialized!');
    }
    return io;
  }
};

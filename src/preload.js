const { io } = require("socket.io-client");
// const { exec } = require("child_process");
// const { app } = require("electron");

console.log("pre-load script active");
// const socket = io();

const socket = io("http://127.0.0.1:8001", { reconnectionDelayMax: 10000 });

socket.on("connect", () => {
  console.log("Connected to the server.");
  // console.log(socket.id); // undefined
});

socket.on("disconnect", () => {
  console.log("Disconnected from the server.");
  // console.log(socket.id); // undefined
  //! add an error page in electron..
});

socket.on("response", (msg) => {
  console.log("The response is :  ", msg);
});

module.exports["socket"] = socket;

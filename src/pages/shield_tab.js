const kill = require("tree-kill");
// const { io } = require("socket.io-client");
const { socket } = require("../preload.js");

const toggle_button = document.querySelector("#shield-tab div#shield-toggle");
let pythonProcessRunning = false;
let pythonProcess = null;
let time_start = null;

const runPythonProcess = (event) => {
  time_start = new Date().getTime();
  pythonProcess = spawn(
    // command,
    "python",
    [
      path.join(__dirname, "../../backend/main.py"), //!
      // "--generate_false_attacks", //! for testing
    ],
    {}
  );

  pythonProcess.stdout.on("data", (data) => {
    if (
      data.toString().trim().length &&
      !data.toString().toLowerCase().includes("warning")
    ) {
      if (data.toString().includes("CONSOLE_LOG")) {
        console.log(data.toString());
      }
      if (data.toString().includes("packet")) {
        console.log(data.toString());
        let packetCount = parseInt(data.toString().trim().split(":")[1].trim());
        console.log("packetssss: ", packetCount);
        if (packetCount == NaN || packetCount === NaN) {
          packetCount = 0;
        }
        addPacket((packetCount / (new Date().getTime() - time_start)) * 10000);
        // update packetCount here
        changeCount(packetCount);
      }

      if (data.toString().includes("MALICIOUS")) {
        let attack_data = JSON.parse(data.toString().split("MALICIOUS: ")[1]);
        attack_data.attackData = JSON.parse(attack_data.attackData);
        // console.log("MALICIOUS:  ", attack_data);
        let temp = JSON.parse(localStorage.getItem("detected_attacks"));
        console.log(temp);
        temp.push(attack_data); //!error if not there in localstorage
        localStorage.setItem("detected_attacks", JSON.stringify(temp));
      }

      /*MALICIOUS: {"attackType": "Probable Zero day attack", "attackData": "{"src_ip": "169.254.90.95", "dst_ip": "169.254.240.26", "src_port": 61494, "dst_port": 80.0, "protocol": 6, "timestamp": "05-07-2023  15:53:34"}"} */
    }
  });

  pythonProcess.stderr.on("data", (data) => {
    console.warn(data.toString());
  });

  pythonProcess.on("close", (code) => {
    console.log(`Python script closed`);
  });

  ipcRenderer.send("python-process", { active: true });
  pythonProcessRunning = true;
  localStorage.setItem("python-process", JSON.stringify({ active: true }));
};

toggle_button.addEventListener(
  "click",
  () => {
    if (pythonProcessRunning) {
      console.log("stopping python process");
      kill(pythonProcess.pid);
      ipcRenderer.send("python-process", { active: false });
      pythonProcessRunning = false;
      localStorage.setItem("python-process", JSON.stringify({ active: false }));
    } else {
      console.log("activating python process");
      runPythonProcess();
    }
  },
  { once: true }
);

toggle_button.addEventListener("click", (e) => {
  console.log(console.log("toggle clickedd"));
});

//! add button click, color, add to attacks list, etc.

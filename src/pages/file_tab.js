// const { socket } = require("../../preload.js"); //socket,ipcRenderer was already imported in realtime.js which is above this file in html.

const { spawn } = require("child_process");
const { ipcRenderer } = require("electron");
const utilsFunctions= require("./utils");
const path = require("path");

const dropArea = document.querySelector("#file-tab .file-upload-box"),
  button = dropArea.querySelector("img.upload-icon"),
  dragText = dropArea.querySelector("p.upload-info-message"),
  input = dropArea.querySelector("input");

const result_box = document.querySelector(".result-box"),
  result_file_name = result_box.querySelector("#result-file-name"),
  result_open_file_img = result_box.querySelector("img#img-open-file");
const result_text = document.querySelector("p.analysis-result-message");
const analysis_result_text = document.querySelector("p.upload-result-message");

var open_file_request;
// var filename;

const view_hide_loader = (view) => {
  if (view) dropArea.querySelector(".loader").style.display = "block";
  else dropArea.querySelector(".loader").style.display = "none";
};

const callPython = (filepath) => {
  const pythonProcess = spawn("python", [
    path.join(__dirname, "../../backend/main.py"),
    "-f",
    filepath,
  ]);

  let analysed_filepath = null;
  let result = null;
  let error = null;

  pythonProcess.stdout.on("data", (data) => {
    const dataString = data.toString();
    console.log(dataString);

    if (dataString.includes("All Benign")) {
      result = "All Benign Connections";
      analysis_result_text.innerHTML = result;
    } else if (dataString.includes("malicious logs detected")) {
      result = dataString.replace(" malicious logs detected, out of ", '/')
      analysis_result_text.innerHTML = `Found <span>${result}</span> malicious packets`;
    }


    if (dataString.includes("Analysed logs saved to:")) {
      analysed_filepath = dataString.split("Analysed logs saved to:")[1].trim();
      console.log("FILE PATH:  ", analysed_filepath);
    }
    // Process the output data from the Python app
  });

  pythonProcess.stderr.on("data", (data) => {
    if (!data.toString().toLowerCase().includes("warning")) {
      console.warn(data.toString());
      error = true;
    }
  });

  pythonProcess.on("close", (code) => {
    console.log(`Python script closed`);

    setTimeout(() => {
      //hiding loader
      view_hide_loader(false);

      //viewing input for file again
      dragText.style.display = "block";
      //   dropArea.querySelector("p").style.display = "inline";
      //   dropArea.querySelector("button").style.display = "block";
      button.style.display = "block";
      
      if (error) {
        utilsFunctions.showNotification("error","Please check the selected file.\n As of now, only log files collected by cicflowmeter and Baboons are supported.")
        result_file_name.innerHTML = `${"Error: "}${error}`;
        result_open_file_img.style.display = "none";
        document.getElementById('upload-error-message').textContent = "*Invalid File";
        document.getElementById('upload-error-message').style.display = "block";
      } else {
        
        result_file_name.innerHTML = path.basename(
          analysed_filepath || filepath
          );
          
        analysis_result_text.style.display = "block";
        document.getElementById('upload-error-message').style.display = "none";
        result_box.style.display = "flex";
        result_text.style.display = "block";
        result_open_file_img.style.display = "block";

        open_file_request = {
          filepath: analysed_filepath || filepath,
          result: result,
        };
      }
    }, 1000);
  });
};

input.addEventListener("change", function (e) {
  var file = e.target.files[0];
  //   dropArea.querySelector("h4").style.display = "none";
  dragText.style.display = "none";
  //   dropArea.querySelector("p").style.display = "none";
  //   dropArea.querySelector("button").style.display = "none";
  button.style.display = "none";

  //   console.log(file.path);
  view_hide_loader(true);
  callPython(file.path);
});

// drag and drop feature for file upload
dropArea.addEventListener('dragenter', (e) => {
  e.preventDefault();
  e.stopPropagation();
});

dropArea.addEventListener('dragover', (e) => {
  e.preventDefault();
  e.stopPropagation();
});

dropArea.addEventListener('dragleave', (e) => {
  e.preventDefault();
  e.stopPropagation();
});

dropArea.addEventListener('drop', (e) => {
  e.preventDefault();
  e.stopPropagation();

  const files = e.dataTransfer.files;
  if(files.length > 1){
    // TODO
    // showNotification('error','You can only upload one file at a time');
    return;
  }

  dragText.style.display = "none";
  button.style.display = "none";
  view_hide_loader(true);
  callPython(files[0].path);
});

dropArea.onclick = () => {
  input.click();
};

// waits till response is received
result_open_file_img.onclick = async () => {

  const res = await utilsFunctions.custom_alert_box(
      "File analysis completed", 
      "Analysed file stored, Do you want to open the analysed file?", 
      "Open Folder", 
      "Open File"
  );

  if(res == 1){
      ipcRenderer.send("open-analysed-folder", open_file_request)
  }

  if(res == 2){
      ipcRenderer.send("open-analysed-file", open_file_request)
  }

};
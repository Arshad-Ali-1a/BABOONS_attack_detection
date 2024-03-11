const dns = require("dns");
const axios = require("axios");
const { hostname } = require("os");

// Custom Alert Box
function custom_alert_box(heading, content, button1, button2) {
  return new Promise((resolve, reject) => {
    const alertbox = document.getElementById("alertBox");
    alertbox.style.display = "flex";
    alertbox.innerHTML = `
            <div class="alert-head">
                <h2>${heading}</h2>
                <img id = "close-alert-box" src="../assets/close.png"/>
            </div>
            
            <p class="alert-content">
                ${content}
            </p>

            <div class="alert-options">
                <button id = "custom_alert_alert_1">${button1}</button>
                <button id = "custom_alert_alert_2">${button2}</button>
            </div>
        `;

    document.getElementById("close-alert-box").onclick = () => {
      close(alertbox);
    };

    document.getElementById("custom_alert_alert_1").onclick = () => {
      resolve(1);
      close(alertbox);
    };

    document.getElementById("custom_alert_alert_2").onclick = () => {
      resolve(2);
      close(alertbox);
    };
  });
}

function close(alertbox) {
  alertbox.style.display = "none";
}

// In app notication
function showNotification(type, message) {
  const notification = document.createElement("div");
  notification.classList.add("notification");

  if (type == "error") {
    notification.innerHTML = `
        <div>
            <img src="../assets/alert.png" alt="">
            <h1>Error</h1>
        </div>
        <p>${message}</p>
        `;
  } else {
    notification.innerHTML = `
        <div>
            <img src="../assets/success.png" alt="">
            <h1>Success</h1>
        </div>
        <p>${message}</p>
        `;
  }

  document.querySelector("body").appendChild(notification);
  setTimeout(() => {
    notification.remove();
  }, 6000);
}

function getDomainName(ipAddress) {
  return new Promise((resolve, reject) => {
    axios
      .get(`https://ipinfo.io/${ipAddress}/json`)
      .then((response) => {
        const data = response.data;
        const hostname = data.hostname || ''; // handle undefined case
        resolve(hostname);
      })
      .catch((error) => {
        reject(error.message);
      });
  });
}

module.exports["custom_alert_box"] = custom_alert_box;
module.exports["showNotification"] = showNotification;
module.exports["getDomainName"] = getDomainName;

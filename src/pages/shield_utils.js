let manual_interface = null
const fs = require('fs');
let currPacketsSpeed=0;
let curInterval = null;
const shieldMainContainer = document.getElementById("main-shield");

const packetHtml = `
  <div class="svg-frame" id="svg-frame">
    <svg style="--i:1; --j:1;transform: scale(1.5);">
        <g id="out2">
            <mask fill="white" id="path-2-inside-2_111_3212">
                <path d="M102.892 127.966C93.3733 142.905 88.9517 160.527 90.2897 178.19L94.3752 177.88C93.1041 161.1 97.3046 144.36 106.347 130.168L102.892 127.966Z"></path>
                <path d="M93.3401 194.968C98.3049 211.971 108.646 226.908 122.814 237.541L125.273 234.264C111.814 224.163 101.99 209.973 97.2731 193.819L93.3401 194.968Z"></path>
                <path d="M152.707 92.3592C140.33 95.3575 128.822 101.199 119.097 109.421L121.742 112.55C130.981 104.739 141.914 99.1897 153.672 96.3413L152.707 92.3592Z"></path>
                <path d="M253.294 161.699C255.099 175.937 253.132 190.4 247.59 203.639L243.811 202.057C249.075 189.48 250.944 175.74 249.23 162.214L253.294 161.699Z"></path>
                <path d="M172 90.0557C184.677 90.0557 197.18 92.9967 208.528 98.6474C219.875 104.298 229.757 112.505 237.396 122.621L234.126 125.09C226.869 115.479 217.481 107.683 206.701 102.315C195.921 96.9469 184.043 94.1529 172 94.1529V90.0557Z"></path>
                <path d="M244.195 133.235C246.991 138.442 249.216 143.937 250.83 149.623L246.888 150.742C245.355 145.34 243.242 140.12 240.586 135.174L244.195 133.235Z"></path>
                <path d="M234.238 225.304C223.932 237.338 210.358 246.126 195.159 250.604C179.961 255.082 163.79 255.058 148.606 250.534L149.775 246.607C164.201 250.905 179.563 250.928 194.001 246.674C208.44 242.42 221.335 234.071 231.126 222.639L234.238 225.304Z"></path>
            </mask>
            <path mask="url(#path-2-inside-2_111_3212)" fill="#fa3939" d="M142.892 127.966L105.579 123.75L101.362 121.063L98.6752 125.28L102.892 127.966ZM90.2897 178.19L85.304 178.567L85.6817 183.553L90.6674 183.175L90.2897 178.19ZM94.3752 177.88L94.7529 182.866L99.7386 182.488L99.3609 177.503L94.3752 177.88ZM106.347 130.168L110.564 132.855L113.251 128.638L109.034 125.951L106.347 130.168ZM93.3401 194.968L91.9387 190.168L87.1391 191.569L88.5405 196.369L93.3401 194.968ZM122.814 237.541L119.813 241.54L123.812 244.541L126.813 240.542L122.814 237.541ZM125.273 234.264L129.272 237.265L132.273 233.266L128.274 230.265L125.273 234.264ZM97.2731 193.819L102.073 192.418L100.671 187.618L95.8717 189.02L97.2731 193.819ZM152.707 92.3592L157.567 91.182L156.389 86.3226L151.53 87.4998L152.707 92.3592ZM119.097 109.421L115.869 105.603L112.05 108.831L115.278 112.649L119.097 109.421ZM121.742 112.55L117.924 115.778L121.152 119.596L124.97 116.368L121.742 112.55ZM153.672 96.3413L154.849 101.201L159.708 100.023L158.531 95.1641L153.672 96.3413ZM253.294 161.699L258.255 161.07L257.626 156.11L252.666 156.738L253.294 161.699ZM247.59 203.639L245.66 208.251L250.272 210.182L252.203 205.569L247.59 203.639ZM243.811 202.057L239.198 200.126L237.268 204.739L241.88 206.669L243.811 202.057ZM249.23 162.214L248.601 157.253L243.641 157.882L244.269 162.842L249.23 162.214ZM172 90.0557V85.0557H167V90.0557H172ZM208.528 98.6474L206.299 103.123L206.299 103.123L208.528 98.6474ZM237.396 122.621L240.409 126.611L244.399 123.598L241.386 119.608L237.396 122.621ZM234.126 125.09L230.136 128.103L233.149 132.093L237.139 129.08L234.126 125.09ZM206.701 102.315L204.473 106.791L204.473 106.791L206.701 102.315ZM172 94.1529H167V99.1529H172V94.1529ZM244.195 133.235L248.601 130.87L246.235 126.465L241.83 128.83L244.195 133.235ZM250.83 149.623L252.195 154.433L257.005 153.067L255.64 148.257L250.83 149.623ZM246.888 150.742L242.078 152.107L243.444 156.917L248.254 155.552L246.888 150.742ZM240.586 135.174L238.22 130.768L233.815 133.134L236.181 137.539L240.586 135.174ZM234.238 225.304L238.036 228.556L241.288 224.759L237.491 221.506L234.238 225.304ZM195.159 250.604L196.572 255.4L196.572 255.4L195.159 250.604ZM148.606 250.534L143.814 249.107L142.386 253.899L147.178 255.326L148.606 250.534ZM149.775 246.607L151.203 241.816L146.411 240.388L144.983 245.18L149.775 246.607ZM194.001 246.674L195.415 251.47L195.415 251.47L194.001 246.674ZM231.126 222.639L234.379 218.841L230.581 215.589L227.329 219.386L231.126 222.639ZM98.6752 125.28C88.5757 141.13 83.8844 159.826 85.304 178.567L95.2754 177.812C94.0191 161.227 98.1709 144.681 107.109 130.653L98.6752 125.28ZM90.6674 183.175L94.7529 182.866L93.9976 172.895L89.912 173.204L90.6674 183.175ZM99.3609 177.503C98.1715 161.8 102.102 146.135 110.564 132.855L102.131 127.481C92.5071 142.585 88.0368 160.4 89.3895 178.258L99.3609 177.503ZM109.034 125.951L105.579 123.75L100.205 132.183L103.661 134.385L109.034 125.951ZM88.5405 196.369C93.8083 214.41 104.78 230.259 119.813 241.54L125.815 233.542C112.512 223.558 102.802 209.532 98.1397 193.566L88.5405 196.369ZM126.813 240.542L129.272 237.265L121.274 231.263L118.815 234.54L126.813 240.542ZM128.274 230.265C115.679 220.813 106.486 207.534 102.073 192.418L92.4735 195.221C97.493 212.412 107.948 227.513 122.272 238.263L128.274 230.265ZM95.8717 189.02L91.9387 190.168L94.7415 199.767L98.6745 198.619L95.8717 189.02ZM151.53 87.4998C138.398 90.681 126.188 96.8793 115.869 105.603L122.325 113.239C131.457 105.519 142.262 100.034 153.884 97.2187L151.53 87.4998ZM115.278 112.649L117.924 115.778L125.56 109.322L122.915 106.193L115.278 112.649ZM124.97 116.368C133.616 109.059 143.846 103.866 154.849 101.201L152.495 91.4818C139.981 94.5132 128.347 100.419 118.514 108.732L124.97 116.368ZM158.531 95.1641L157.567 91.182L147.848 93.5364L148.812 97.5185L158.531 95.1641ZM248.334 162.327C250.028 175.697 248.181 189.277 242.978 201.708L252.203 205.569C258.082 191.522 260.169 176.177 258.255 161.07L248.334 162.327ZM249.521 199.027L245.741 197.445L241.88 206.669L245.66 208.251L249.521 199.027ZM248.423 203.987C254.025 190.602 256.014 175.98 254.19 161.585L244.269 162.842C245.873 175.5 244.125 188.357 239.198 200.126L248.423 203.987ZM249.858 167.174L253.923 166.659L252.666 156.738L248.601 157.253L249.858 167.174ZM172 95.0557C183.903 95.0557 195.644 97.8172 206.299 103.123L210.757 94.1717C198.717 88.1761 185.45 85.0557 172 85.0557V95.0557ZM206.299 103.123C216.954 108.429 226.233 116.135 233.406 125.634L241.386 119.608C233.281 108.874 222.796 100.167 210.757 94.1717L206.299 103.123ZM234.383 118.631L231.113 121.1L237.139 129.08L240.409 126.611L234.383 118.631ZM238.116 122.077C230.393 111.849 220.403 103.552 208.93 97.8393L204.473 106.791C214.56 111.814 223.345 119.11 230.136 128.103L238.116 122.077ZM208.93 97.8393C197.458 92.1263 184.816 89.1529 172 89.1529V99.1529C183.269 99.1529 194.385 101.767 204.473 106.791L208.93 97.8393ZM177 94.1529V90.0557H167V94.1529H177ZM239.79 135.601C242.416 140.49 244.504 145.649 246.02 150.988L255.64 148.257C253.927 142.225 251.567 136.395 248.601 130.87L239.79 135.601ZM249.464 144.813L245.523 145.932L248.254 155.552L252.195 154.433L249.464 144.813ZM251.698 149.376C250.067 143.628 247.818 138.073 244.991 132.808L236.181 137.539C238.666 142.168 240.644 147.052 242.078 152.107L251.698 149.376ZM242.951 139.579L246.561 137.64L241.83 128.83L238.22 130.768L242.951 139.579ZM230.441 222.051C220.763 233.351 208.017 241.603 193.746 245.808L196.572 255.4C212.698 250.649 227.101 241.325 238.036 228.556L230.441 222.051ZM193.746 245.808C179.475 250.012 164.291 249.99 150.033 245.742L147.178 255.326C163.289 260.125 180.447 260.151 196.572 255.4L193.746 245.808ZM153.397 251.962L154.567 248.035L144.983 245.18L143.814 249.107L153.397 251.962ZM148.348 251.399C163.7 255.973 180.049 255.997 195.415 251.47L192.588 241.877C179.077 245.858 164.702 245.837 151.203 241.816L148.348 251.399ZM195.415 251.47C210.78 246.942 224.504 238.058 234.924 225.891L227.329 219.386C218.167 230.084 206.099 237.897 192.588 241.877L195.415 251.47ZM227.874 226.436L230.986 229.101L237.491 221.506L234.379 218.841L227.874 226.436Z"></path>
        </g>
    </svg>

    <svg style="--i:1;--j:3;transform: scale(1.5);">
        <g id="inner1">
            <path fill="#fa3939" d="M145.949 124.51L148.554 129.259C156.575 124.859 165.672 122.804 174.806 123.331C183.94 123.858 192.741 126.944 200.203 132.236C207.665 137.529 213.488 144.815 217.004 153.261C220.521 161.707 221.59 170.972 220.09 179.997L224.108 180.665L224.102 180.699L229.537 181.607C230.521 175.715 230.594 169.708 229.753 163.795L225.628 164.381C224.987 159.867 223.775 155.429 222.005 151.179C218.097 141.795 211.628 133.699 203.337 127.818C195.045 121.937 185.266 118.508 175.118 117.923C165.302 117.357 155.525 119.474 146.83 124.037C146.535 124.192 146.241 124.349 145.949 124.51ZM224.638 164.522C224.009 160.091 222.819 155.735 221.082 151.563C217.246 142.352 210.897 134.406 202.758 128.634C194.62 122.862 185.021 119.496 175.06 118.922C165.432 118.367 155.841 120.441 147.311 124.914L148.954 127.91C156.922 123.745 165.876 121.814 174.864 122.333C184.185 122.87 193.166 126.019 200.782 131.421C208.397 136.822 214.339 144.257 217.928 152.877C221.388 161.188 222.526 170.276 221.23 179.173L224.262 179.677C224.998 174.671 225.35 169.535 224.638 164.522Z" clip-rule="evenodd" fill-rule="evenodd"></path>
            <path fill="#fa3939" d="M139.91 220.713C134.922 217.428 130.469 213.395 126.705 208.758L130.983 205.286L130.985 205.288L134.148 202.721C141.342 211.584 151.417 217.642 162.619 219.839C173.821 222.036 185.438 220.232 195.446 214.742L198.051 219.491C197.759 219.651 197.465 219.809 197.17 219.963C186.252 225.693 173.696 227.531 161.577 225.154C154.613 223.789 148.041 221.08 142.202 217.234L139.91 220.713ZM142.752 216.399C148.483 220.174 154.934 222.833 161.769 224.173C173.658 226.504 185.977 224.704 196.689 219.087L195.046 216.09C185.035 221.323 173.531 222.998 162.427 220.82C151.323 218.643 141.303 212.747 134.01 204.122L131.182 206.5C134.451 210.376 138.515 213.607 142.752 216.399Z" clip-rule="evenodd" fill-rule="evenodd"></path>
        </g>
    </svg>

    <p id="count">Loading...</p>
  </div>
  <button class="disable-button" onclick="disableFromButton()">Disable Shield</button>
`
const data = {
  labels: [],
  datasets: [{
    label: 'Packets Collected',
    data: [],
    fill: false,
    borderColor: 'rgb(75, 192, 192)',
    tension: 0.1
  }]
};

const config = {
  type: 'line',
  data: data,
  options: {
    scales: {
      y: {
        beginAtZero: true
      }
    }
  }
};

// Function to set the network interface to be used for the shield
function setInterface(){
    const interfaceInput = document.getElementById('interface-input');
    manual_interface = interfaceInput.value;
}

const myChart = new Chart(
    document.getElementById('myChart'),
    config
)

// call this function when you want to add new data
function addData(chart, data) {
  console.log("sdfsdf: ", data)
  if(data == NaN || data === NaN){
    return;
  }
  const now = new Date();
  const time = now.getHours().toString().padStart(2, '0') + ':' +
              now.getMinutes().toString().padStart(2, '0') + ':' +
              now.getSeconds().toString().padStart(2, '0');

  if (chart.data.datasets[0].data.length >= 10) {
      chart.data.labels.shift()
      chart.data.datasets[0].data.shift();
  }

  
  chart.data.labels.push(time);           // TODO: adding new label [Time]
  chart.data.datasets[0].data.push(data)  // TODO: adding new data [Packet Count]
  chart.update();
}

function changeCount(packet){
  if(document.getElementById("count") != null){
    if(packet){
      document.getElementById("count").textContent = packet;
    }
  }
}

// function to Switch on and off the shield
function toggleShield(){
  const toggleElement = document.getElementById("shield-toggle");
  const shield = document.getElementById("shield-toggle-section");
  const shieldImage = document.getElementById("shield-image");
  let isOff = (toggleElement.classList.value).includes("off");

  if(isOff){
    console.log("Switching on")
    toggleElement.classList.toggle("off");
    toggleElement.classList.toggle("on");
    shield.classList.toggle("red")
    shield.classList.toggle("green")
    setTimeout(() => {
      shield.style.animationName = 'fadeOutScaleDown';
      shield.style.animationDuration = '0.8s';
      shield.style.animationFillMode = 'forwards';

      shieldMainContainer.innerHTML = packetHtml;
      const packetContainer = document.getElementById("svg-frame")
      packetContainer.style.animationName = 'fadeInScaleUp';
      packetContainer.style.animationDuration = '0.8s';
      packetContainer.style.animationFillMode = 'forwards';
    }, 500)
    shieldImage.src = "../assets/menu2.png"
    document.getElementById("shield-status-heading").textContent = "Shield is Active"
    document.getElementById("shield-status-caption").textContent = "Protecting your system from malicious traffic."
    currPacketsSpeed=0;
    activateShield();
  }
  else{
    // turning it off
    console.log("Switching off")
    toggleElement.classList.toggle("off");
    toggleElement.classList.toggle("on");
    shield.classList.toggle("red");
    shield.classList.toggle("green");
    setTimeout(() => {
      toggleElement.style.animationName = 'fadeInScaleUp';
      toggleElement.style.animationDuration = '0.8s';
      toggleElement.style.animationFillMode = 'forwards';

      const packetContainer = document.getElementById("svg-frame")
      packetContainer.style.animationName = 'fadeOutScaleDown';
      packetContainer.style.animationDuration = '0.8s';
      packetContainer.style.animationFillMode = 'forwards';
    }, 800);

    shieldImage.src = "../assets/alert.png"
    document.getElementById("shield-status-heading").textContent = "Shield is Disabled"
    document.getElementById("shield-status-caption").textContent = "Click on the toggle button to activate it."
    disableShield();
  }
}

function addPacket(packetCount){
  currPacketsSpeed=parseInt(packetCount);
}

function activateShield(){
    curInterval = setInterval(() => {
      if(currPacketsSpeed !== NaN && currPacketsSpeed != NaN){
        addData(myChart, currPacketsSpeed)
      }
    }, 3000)
}

function disableShield(){
  if(curInterval == null) return;

  clearInterval(curInterval);
  curInterval = null;
}

function disableFromButton(){
  console.log(pythonProcess);
  const packetContainer = document.getElementById("svg-frame")
  packetContainer.style.animationName = 'fadeOutScaleDown';
  packetContainer.style.animationDuration = '0.8s';
  packetContainer.style.animationFillMode = 'forwards';
  document.getElementsByClassName("disable-button")[0].remove();
  
  setTimeout(() => {
    shieldMainContainer.innerHTML = `
      <div id = "shield-toggle-section" class = "sheild-toggle-section red">
        <img id = "shield-image" src="../assets/alert.png" alt=""> 
        <div onclick="toggleShield()" id = "shield-toggle" class="toggle off">
            <div class="toggle-handle"></div>
        </div>
      </div>
      <div class = "sheild-text">
        <h1 class="shield-status" id = "shield-status-heading">Shield is Disabled</h1>
        <p id = "shield-status-caption"> Click on the toggle button to activate it.</p>
      </div>
    `

    shieldMainContainer.style.animationName = 'fadeInScaleUp';
    shieldMainContainer.style.animationDuration = '1s';
    shieldMainContainer.style.animationFillMode = 'forwards';
    
  
    document.getElementById('shield-image').src = "../assets/alert.png"
    document.getElementById("shield-status-heading").textContent = "Shield is Disabled"
    document.getElementById("shield-status-caption").textContent = "Click on the toggle button to activate it."
    disableShield();

    if (pythonProcessRunning) {
      console.log("stopping python process");
      kill(pythonProcess.pid);
      ipcRenderer.send("python-process", { active: false });
      pythonProcessRunning = false;
      localStorage.setItem("python-process", JSON.stringify({ active: false }));
    }
  
    document.querySelector("#shield-tab div#shield-toggle").addEventListener("click", () => {
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
    }, {once:true});
  },800);

  
}

/* Unblocking the IP addresses */
const runPythonProcessUnblock = (ip_address) => {
  pythonProcess = spawn(
    "python",
    [path.join(__dirname, "../../backend/main.py"), "--unblock_ip", ip_address],
  );

  pythonProcess.stdout.on('data', (data) => {
    console.log(`stdout: ${data}`);
  });

  pythonProcess.stderr.on('data', (data) => {
    console.error(`stderr: ${data}`);
  });

  pythonProcess.on('close', (code) => {
    console.log(`child process exited with code ${code}`);
    fetchBlockedIPs()
  });
};


function fetchBlockedIPs(){
  const filePath = path.join(__dirname, "../../backend/watchWarden_blocked_ips.json")
  const blocked_ips = fs.readFileSync(filePath, 'utf8');
  const blocked_ips_json = JSON.parse(blocked_ips);
  const container = document.getElementById("block-ips-body");

  if(blocked_ips_json.length == 0){
    container.innerHTML = `<h2 style="text-align:center">No Blocked IPs</h2>`
    return;
  }

  container.innerHTML = ""

  blocked_ips_json.forEach((ip) => {
    const blockContainer = document.createElement('div');
    blockContainer.classList.add('ip-container');
    const unblockButton = document.createElement("button");
    unblockButton.textContent = "Unblock";

    blockContainer.innerHTML = `
        <h1>IP Address: <span>${ip}</span></h1>
    `
    blockContainer.appendChild(unblockButton);

    unblockButton.addEventListener('click', () => {
      runPythonProcessUnblock(ip);
    })
    container.appendChild(blockContainer);

  })
}

fetchBlockedIPs()

// packet count
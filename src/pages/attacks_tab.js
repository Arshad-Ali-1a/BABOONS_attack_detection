const attacksSideBar = document.getElementById("attacks-sidebar");
const attackDetailsEl = document.getElementById("attack-details");
const { nanoid } = require("nanoid");

const pencilLoaderHtml = `
<svg xmlns="http://www.w3.org/2000/svg" height="200px" width="200px" viewBox="0 0 200 200" class="pencil">
    <defs>
        <clipPath id="pencil-eraser">
            <rect height="30" width="30" ry="5" rx="5"></rect>
        </clipPath>
    </defs>
    <circle transform="rotate(-113,100,100)" stroke-linecap="round" stroke-dashoffset="439.82" stroke-dasharray="439.82 439.82" stroke-width="2" stroke="currentColor" fill="none" r="70" class="pencil__stroke"></circle>
    <g transform="translate(100,100)" class="pencil__rotate">
        <g fill="none">
            <circle transform="rotate(-90)" stroke-dashoffset="402" stroke-dasharray="402.12 402.12" stroke-width="30" stroke="hsl(223,90%,50%)" r="64" class="pencil__body1"></circle>
            <circle transform="rotate(-90)" stroke-dashoffset="465" stroke-dasharray="464.96 464.96" stroke-width="10" stroke="hsl(223,90%,60%)" r="74" class="pencil__body2"></circle>
            <circle transform="rotate(-90)" stroke-dashoffset="339" stroke-dasharray="339.29 339.29" stroke-width="10" stroke="hsl(223,90%,40%)" r="54" class="pencil__body3"></circle>
        </g>
        <g transform="rotate(-90) translate(49,0)" class="pencil__eraser">
            <g class="pencil__eraser-skew">
                <rect height="30" width="30" ry="5" rx="5" fill="hsl(223,90%,70%)"></rect>
                <rect clip-path="url(#pencil-eraser)" height="30" width="5" fill="hsl(223,90%,60%)"></rect>
                <rect height="20" width="30" fill="hsl(223,10%,90%)"></rect>
                <rect height="20" width="15" fill="hsl(223,10%,70%)"></rect>
                <rect height="20" width="5" fill="hsl(223,10%,80%)"></rect>
                <rect height="2" width="30" y="6" fill="hsla(223,10%,10%,0.2)"></rect>
                <rect height="2" width="30" y="13" fill="hsla(223,10%,10%,0.2)"></rect>
            </g>
        </g>
        <g transform="rotate(-90) translate(49,-30)" class="pencil__point">
            <polygon points="15 0,30 30,0 30" fill="hsl(33,90%,70%)"></polygon>
            <polygon points="15 0,6 30,0 30" fill="hsl(33,90%,50%)"></polygon>
            <polygon points="15 0,20 10,10 10" fill="hsl(223,10%,10%)"></polygon>
        </g>
    </g>
</svg>
`;

function fetchData() {
  let incoming_data = JSON.parse(localStorage.getItem("detected_attacks"));
  if (incoming_data == null || incoming_data == undefined) {
    return;
  }

  let currActiveEl = null;
  let firstTime = true;

  incoming_data.forEach((data) => {
    const timestampElement = document.createElement("p");
    // timestampElement.textContent = getTimeStamp(new Date(data.timestamp));
    const timestamp = new Date().toLocaleString();
    timestampElement.textContent = timestamp;

    timestampElement.onclick = () => {
      attackDetailsEl.innerHTML = pencilLoaderHtml;

      const attackData = data.attackData;
      const attackType = data.attackType;
      createAttack(attackData, attackType, timestamp)
        .then((result) => {
          //   const timestamp = new Date().toLocaleString();
          const attackDetails = result[timestamp];
          console.log(attackDetails);
          attackDetailsEl.innerHTML = `
                        <div>
                            <p class = "detail-heading">Source IP</p>
                            <p class = "detail-content">${attackDetails["Source IP"]}</p>
                        </div>
    
                        <div>
                            <p class = "detail-heading">Destination IP</p>
                            <p class = "detail-content">${attackDetails["Destination IP"]}</p>
                        </div>
    
                        <div>
                            <p class = "detail-heading">Domain Name</p>
                            <p class = "detail-content">${attackDetails["Domain name"]}</p>
                        </div>
    
                        <div>
                            <p class = "detail-heading">Port Number</p>
                            <p class = "detail-content">${attackDetails["Port Number"]}</p>
                        </div>
    
                        <div>
                            <p class = "detail-heading">Attack</p>
                            <p class = "detail-content">${attackDetails["Attack Type"]}</p>
                        </div>
    
                        <div>
                            <p class = "detail-heading">Threat Level</p>
                            <p class = "detail-content">${attackDetails["Threat Level"]}</p>
                        </div>
                    `;
        })
        .catch((error) => {
          console.log(error);
        });

      if (currActiveEl == null) {
        currActiveEl = timestampElement;
        currActiveEl.classList.add("active-timestamp");
      } else {
        currActiveEl.classList.remove("active-timestamp");
        currActiveEl = timestampElement;
        currActiveEl.classList.add("active-timestamp");
      }
    };
    attacksSideBar.appendChild(timestampElement);

    if (firstTime) {
      attacksSideBar.firstElementChild.click();
      firstTime = false;
    }
  });
}

fetchData();

async function createAttack(attackData, attackType, timestamp) {
  try {
    let domainName = await getDomainName(attackData.dst_ip);

    if (domainName.length == 0) {
      domainName = "Not Available";
    }
    if (attackData.threatLevel == undefined) {
      attackData.threatLevel = "Avengers Level Threat";
    }
    const processedAttacksDetails = {
      id: nanoid(),
      "Source IP": attackData.src_ip,
      "Destination IP": attackData.dst_ip,
      "Domain name": domainName,
      "Port Number": attackData.dst_port,
      "Attack Type": attackType,
      "Threat Level": attackData.threatLevel,
    };

    const processed = {
      [timestamp]: processedAttacksDetails,
    };

    return processed;
  } catch (error) {
    console.error(error);
    return null;
  }
}

function getTimeStamp(timestampInput) {
  let timestamp = timestampInput.replace(/\s+/g, " "); // replace multiple spaces with a single space
  let [day, month, yearTime] = timestamp.split("-");
  let [year, time] = yearTime.split(" ");
  let [hours, minutes, seconds] = time.split(":");

  let date = new Date(year, month - 1, day, hours, minutes, seconds);

  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "numeric",
    hour12: true,
  });
}

const main_tabs = ["home-tab", "file-tab", "shield-tab", "attacks-tab"]
const components = ["comp-interface", "comp-stats", "comp-blocks"]

// Switching main tabs
function changeTab(tabName){

    document.getElementById("home").classList.remove("active-tab");
    document.getElementById("file").classList.remove("active-tab");
    document.getElementById("shield").classList.remove("active-tab");
    document.getElementById("attacks").classList.remove("active-tab");
    
    main_tabs.forEach(tab => {
        if(tab.includes(tabName)){
            document.getElementById(tab).style.display = "flex";
            document.getElementById(tabName).classList.add("active-tab");
        }
        else{
            document.getElementById(tab).style.display = "none";
        }
    });
}

// Swtiching components
function changeComponent(componentName){
    components.forEach(component => {
        if(component.includes(componentName)){
            document.getElementById(component).style.display = "flex";
        }
        else{
            document.getElementById(component).style.display = "none";
        }
    });
}


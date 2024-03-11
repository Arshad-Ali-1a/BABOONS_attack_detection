const { app, BrowserWindow, ipcMain, dialog, shell } = require("electron");
const path = require("path");
const {exec} = require("child_process");

function handleAdminRights() {
  const handleAdminRights_closeApp = (is_admin) => {
    console.log(is_admin);
    if (is_admin == "not admin") {
      console.log("please start application with admin rights.");

      // exec("exit");
      dialog
        .showMessageBox(mainWindow, {
          message: "Admin rights required",
          type: "info",
          title: "Watch Warden",
          detail:
            "Please start the application with admin rights, else application might not work properly.\n Exit the application?",
          buttons: ["Cancel", "OK"],
        })
        .then((result) => {
          if (result.response === 1) {
            app.exit();
          }
        })
        .catch((err) => {
          console.warn(err);
        });
    }
  };

  if (process.platform == "win32") {
    console.log("running on windows");

    exec("NET SESSION", function (err, so, se) {
      let is_admin = se.length === 0 ? "admin" : "not admin";
      handleAdminRights_closeApp(is_admin);
    });
  } else if (process.platform == "darwin") {
    console.log("running on mac");
    exec("sudo -n uptime", function (err, stdout, stderr) {
      let is_admin = err ? "not admin" : "admin";
      handleAdminRights_closeApp(is_admin);
    });
  } else {
    console.log("platform not supported, exiting..");
    // exec("exit");
    app.quit();
  }
}

// to force only one instance of app at one time.
const isFirstInstance = app.requestSingleInstanceLock();
if (!isFirstInstance) {
  app.quit();
  return;
}

let mainWindow = null;

const createWindow = () => {
  // Create the browser window.
  mainWindow = new BrowserWindow({
    width: 1430,
    height: 750,
    // backgroundColor: "#a7dce2",
    show: false,
    // titleBarStyle: "hidden",
    // titleBarOverlay: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      nodeIntegration: true,
      contextIsolation: false,
      contentSecurityPolicy: "default-src 'self' file: 'unsafe-inline'",
    },
    // icon: path.join(__dirname, "./assets/icon.png"),
    // resizable: false, //!!disable later
    autoHideMenuBar: true,
  });

  mainWindow.loadFile(path.join(__dirname, "./pages/HomePage.html"));

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
    // handleAdminRights();
    //!! uncomment the handleAdminRights function.
  });

  // Open the DevTools.
  // mainWindow.webContents.openDevTools();
};

app.on("ready", () => {
  createWindow();
  //TODO createTray();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  // On OS X it's common to re-create a window in the app when the
  // dock icon is clicked and there are no other windows open.
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// ipcMain.on("open-file", (event, data) => {
//   dialog
//     .showMessageBox(mainWindow, {
//       message: data.result || "",
//       type: "info",
//       title: "File analysis completed",
//       detail: "Analysed file stored, Do you want to open the analysed file?",
//       buttons: ["Cancel", "OK"],
//     })
//     .then((result) => {
//       if (result.response === 1) {
//         shell.showItemInFolder(data.filepath);
//       }
//     })
//     .catch((err) => {
//       console.warn(err);
//     });
// });

ipcMain.on("open-analysed-folder", (event, data) => {
  shell.showItemInFolder(data.filepath);
});

ipcMain.on("open-analysed-file", (event, data) => {
  exec(`start excel "${data.filepath}"`, (err) => {
    if (err) {
        console.error(err);
    }
});
})

ipcMain.on("open-file-error", (event, data) => {
  // console.log(data);
  dialog.showErrorBox(
    (title = "Something went wrong"),
    (content =
      "Please check the selected file.\n As of now, only log files collected by cicflowmeter and watchwarden are supported.")
  );
});

//TODO: pthon process start, and communication
//TODO: file open, upload things..
//TODO: app autostart on shutdown... set login item settings
//TODO: Tray.. skip tray.. go to tray, etc

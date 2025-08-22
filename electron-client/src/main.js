import { app, BrowserWindow, ipcMain } from "electron";
import path from "path";
import { fileURLToPath } from "url";
import { activate, heartbeat, deactivate, isValid } from "./main-secure/license-core.js";
import { getHWID, verifyWithLaravel } from "./renderer/hwid.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
let mainWindow = null;
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 700,
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            nodeIntegration: false,
            contextIsolation: true,
        },
    });
    mainWindow.loadFile(path.join(__dirname, "renderer/index.html"));
    mainWindow.on("closed", () => { mainWindow = null; });
}
app.on("ready", createWindow);
app.on("window-all-closed", () => {
    if (process.platform !== "darwin")
        app.quit();
});
app.on("activate", () => {
    if (!mainWindow)
        createWindow();
});
// License IPC
ipcMain.handle("license:activate", (_, key) => activate(key));
ipcMain.handle("license:heartbeat", () => heartbeat());
ipcMain.handle("license:deactivate", () => deactivate());
ipcMain.handle("license:isValid", () => isValid());
// HWID IPC
ipcMain.handle("hwid:get", () => getHWID());
ipcMain.handle("hwid:verify", (_, license) => verifyWithLaravel(license));

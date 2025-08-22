import { contextBridge, ipcRenderer } from "electron";

/**
 * Expose License functions (activate, heartbeat, deactivate, isValid)
 * This talks to your main process -> license.ts -> Laravel backend
 */
contextBridge.exposeInMainWorld("api", {
  license: {
    activate: (key: string) => ipcRenderer.invoke("license:activate", key),
    heartbeat: () => ipcRenderer.invoke("license:heartbeat"),
    deactivate: () => ipcRenderer.invoke("license:deactivate"),
    isValid: () => ipcRenderer.invoke("license:isValid"),
  },
});

/**
 * Expose HWID + Verify API
 * This goes through hwid.ts (reads HWID via DLL/OS) and sends to Laravel
 */
contextBridge.exposeInMainWorld("licenseAPI", {
  getHWID: () => ipcRenderer.invoke("hwid:get"),
  verifyLicense: (license: string) => ipcRenderer.invoke("hwid:verify", license),
});

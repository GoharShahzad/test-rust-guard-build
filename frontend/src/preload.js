const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getHardwareId: () => ipcRenderer.invoke('get-hardware-id'),
  createLicenseToken: (licenseKey, hardwareId, secret) => 
    ipcRenderer.invoke('create-license-token', licenseKey, hardwareId, secret),
  verifyLicenseToken: (token, secret) => 
    ipcRenderer.invoke('verify-license-token', token, secret)
});
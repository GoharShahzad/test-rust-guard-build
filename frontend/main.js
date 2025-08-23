const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const ffi = require('ffi-napi');
const fs = require('fs');
const { execSync, spawn } = require('child_process');

// Load Rust library
let rustLib;
try {
  const rustLibPath = process.env.NODE_ENV === 'development' 
    ? path.join(__dirname, 'rust-module/target/debug/libelectron_secure_module')
    : path.join(process.resourcesPath, 'libelectron_secure_module');

  rustLib = ffi.Library(rustLibPath, {
    'generate_composite_hardware_id': ['string', []],
    'generate_key_pair': ['string', []],
    'sign_data': ['string', ['string', 'string']],
    'verify_signature': ['bool', ['string', 'string', 'string']],
    'create_license_token': ['string', ['string', 'string', 'string', 'string']],
    'verify_license_token': ['bool', ['string', 'string']],
    'get_token_claims': ['string', ['string', 'string']],
    'is_debugger_present': ['bool', []],
    'free_c_string': ['void', ['string']]
  });
} catch (error) {
  console.error('Failed to load Rust library:', error);
  dialog.showErrorBox('Initialization Error', 'Failed to load security module. The application cannot start.');
  app.quit();
}

let mainWindow;

// Verify code signature (Windows)
function verifyCodeSignature() {
  if (process.platform !== 'win32') return true; // Skip on non-Windows
  
  try {
    const exePath = process.execPath;
    const command = `Get-AuthenticodeSignature -FilePath "${exePath}" | Select-Object Status, StatusMessage`;
    
    const result = execSync(`powershell -Command "${command}"`, { encoding: 'utf8' });
    
    if (result.includes('Valid')) {
      console.log('Code signature is valid');
      return true;
    } else {
      console.error('Invalid code signature:', result);
      return false;
    }
  } catch (error) {
    console.error('Failed to verify code signature:', error);
    return false;
  }
}

// Anti-tampering measures
function checkIntegrity() {
  try {
    // Verify code signature
    if (!verifyCodeSignature()) {
      return false;
    }

    // Check if running in debug mode
    if (process.execArgv.some(arg => arg.includes('--inspect') || arg.includes('--remote-debugging-port'))) {
      console.error('Debug mode detected');
      return false;
    }

    // Check if file has been modified
    const packagePath = path.join(process.resourcesPath, 'app.asar');
    if (fs.existsSync(packagePath)) {
      const stats = fs.statSync(packagePath);
      const now = new Date();
      const diffTime = Math.abs(now - stats.mtime);
      const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      
      if (diffDays < 1) {
        console.error('Application recently modified');
        return false;
      }
    }

    return true;
  } catch (error) {
    console.error('Integrity check failed:', error);
    return false;
  }
}

// Check if debugger is present using Rust function
if (rustLib.is_debugger_present()) {
  console.error('Debugger detected');
  dialog.showErrorBox('Security Violation', 'Debugger detected. Application will now exit.');
  app.quit();
}

function createWindow() {
  // Perform integrity check
  if (!checkIntegrity()) {
    dialog.showErrorBox('Security Violation', 'Application integrity check failed. Please reinstall the application.');
    app.quit();
    return;
  }

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
      enableRemoteModule: false,
      contextIsolation: true
    },
    icon: path.join(__dirname, 'assets/icon.png'),
    show: false
  });

  // Load the app
  mainWindow.loadFile('src/index.html');
  
  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
  });
  
  // Development tools only in development
  if (process.env.NODE_ENV === 'development') {
    mainWindow.webContents.openDevTools();
  }

  // Prevent DevTools in production
  mainWindow.webContents.on('devtools-opened', () => {
    if (process.env.NODE_ENV !== 'development') {
      mainWindow.webContents.closeDevTools();
      dialog.showErrorBox('Security Violation', 'Developer tools are not allowed.');
    }
  });

  // Implement runtime integrity checks
  setInterval(() => {
    if (rustLib.is_debugger_present()) {
      dialog.showErrorBox('Security Violation', 'Debugger detected. Application will now exit.');
      app.quit();
    }
    
    // Verify application files haven't been modified
    if (!checkIntegrity()) {
      dialog.showErrorBox('Security Violation', 'Application integrity check failed. Please reinstall the application.');
      app.quit();
    }
  }, 30000); // Check every 30 seconds
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

// Enhanced IPC handlers
ipcMain.handle('get-hardware-id', () => {
  const hwid = rustLib.generate_composite_hardware_id();
  return hwid;
});

ipcMain.handle('generate-key-pair', () => {
  const keyPair = rustLib.generate_key_pair();
  return keyPair;
});

ipcMain.handle('sign-data', (event, data, privateKey) => {
  const signature = rustLib.sign_data(data, privateKey);
  return signature;
});

ipcMain.handle('verify-signature', (event, data, signature, publicKey) => {
  return rustLib.verify_signature(data, signature, publicKey);
});

ipcMain.handle('create-license-token', (event, licenseKey, hardwareId, secret, tokenId) => {
  const token = rustLib.create_license_token(licenseKey, hardwareId, secret, tokenId);
  return token;
});

ipcMain.handle('verify-license-token', (event, token, secret) => {
  return rustLib.verify_license_token(token, secret);
});

ipcMain.handle('get-token-claims', (event, token, secret) => {
  const claims = rustLib.get_token_claims(token, secret);
  return claims;
});
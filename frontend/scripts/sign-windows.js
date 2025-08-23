const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const config = {
  certificatePath: process.env.CERTIFICATE_PATH || 'certificate.pfx',
  certificatePassword: process.env.CERTIFICATE_PASSWORD || 'your_password',
  timestampServer: 'http://timestamp.digicert.com',
  executablePath: process.env.EXECUTABLE_PATH || 'dist/Secure To-Do Setup 1.0.0.exe'
};

function signWindowsExecutable() {
  try {
    if (!fs.existsSync(config.executablePath)) {
      throw new Error(`Executable not found: ${config.executablePath}`);
    }

    if (!fs.existsSync(config.certificatePath)) {
      throw new Error(`Certificate not found: ${config.certificatePath}`);
    }

    console.log('Signing Windows executable...');
    
    const signToolPath = findSignTool();
    const command = `"${signToolPath}" sign /f "${config.certificatePath}" /p "${config.certificatePassword}" /fd sha256 /tr "${config.timestampServer}" /td sha256 /v "${config.executablePath}"`;
    
    console.log(`Executing: ${command}`);
    execSync(command, { stdio: 'inherit' });
    
    console.log('Executable signed successfully');
  } catch (error) {
    console.error('Failed to sign executable:', error.message);
    process.exit(1);
  }
}

function findSignTool() {
  // Look for signtool in common locations
  const possiblePaths = [
    'C:\\Program Files (x86)\\Windows Kits\\10\\bin\\**\\x64\\signtool.exe',
    'C:\\Program Files (x86)\\Windows Kits\\10\\bin\\**\\x86\\signtool.exe',
    'C:\\Program Files (x86)\\Windows Kits\\8.1\\bin\\**\\x64\\signtool.exe',
    'C:\\Program Files (x86)\\Windows Kits\\8.1\\bin\\**\\x86\\signtool.exe'
  ];
  
  for (const pathPattern of possiblePaths) {
    try {
      const result = execSync(`where "${pathPattern}"`, { encoding: 'utf8' });
      if (result.trim()) {
        return result.trim().split('\r\n')[0];
      }
    } catch (error) {
      // Continue searching
    }
  }
  
  throw new Error('SignTool not found. Please install Windows SDK');
}

signWindowsExecutable();
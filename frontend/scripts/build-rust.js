const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

function buildRustModule() {
  try {
    console.log('Building Rust module...');
    
    // Change to rust module directory
    const rustModuleDir = path.join(__dirname, '..', 'frontend', 'rust-module');
    process.chdir(rustModuleDir);
    
    // Build the Rust module
    execSync('cargo build --release', { stdio: 'inherit' });
    
    // Copy the built library to the target directory
    const targetDir = path.join(__dirname, '..', 'frontend', 'target', 'release');
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
    
    let sourceFile, destFile;
    if (process.platform === 'win32') {
      sourceFile = path.join(rustModuleDir, 'target', 'release', 'electron_secure_module.dll');
      destFile = path.join(targetDir, 'libelectron_secure_module.node');
    } else if (process.platform === 'darwin') {
      sourceFile = path.join(rustModuleDir, 'target', 'release', 'libelectron_secure_module.dylib');
      destFile = path.join(targetDir, 'libelectron_secure_module.node');
    } else {
      sourceFile = path.join(rustModuleDir, 'target', 'release', 'libelectron_secure_module.so');
      destFile = path.join(targetDir, 'libelectron_secure_module.node');
    }
    
    if (fs.existsSync(sourceFile)) {
      fs.copyFileSync(sourceFile, destFile);
      console.log(`Rust module copied to: ${destFile}`);
    } else {
      throw new Error(`Rust module not found at: ${sourceFile}`);
    }
    
    console.log('Rust module built successfully');
  } catch (error) {
    console.error('Failed to build Rust module:', error.message);
    process.exit(1);
  }
}

buildRustModule();
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const javascriptObfuscator = require('javascript-obfuscator');

module.exports = async function (context) {
  // Obfuscate JavaScript files
  const appPath = context.appOutDir;
  const asarPath = path.join(appPath, 'resources', 'app.asar');
  
  // Extract asar archive
  execSync(`npx asar extract ${asarPath} ./app-unpacked`);
  
  // Obfuscate all JavaScript files
  const walkDir = function(dir, callback) {
    fs.readdirSync(dir).forEach(f => {
      let dirPath = path.join(dir, f);
      let isDirectory = fs.statSync(dirPath).isDirectory();
      isDirectory ? walkDir(dirPath, callback) : callback(path.join(dir, f));
    });
  };
  
  walkDir('./app-unpacked', function(filePath) {
    if (filePath.endsWith('.js')) {
      const code = fs.readFileSync(filePath, 'utf8');
      const obfuscatedCode = javascriptObfuscator.obfuscate(code, {
        compact: true,
        controlFlowFlattening: true,
        controlFlowFlatteningThreshold: 0.75,
        deadCodeInjection: true,
        deadCodeInjectionThreshold: 0.4,
        debugProtection: true,
        debugProtectionInterval: 4000,
        disableConsoleOutput: true,
        identifierNamesGenerator: 'hexadecimal',
        log: false,
        numbersToExpressions: true,
        renameGlobals: false,
        selfDefending: true,
        simplify: true,
        splitStrings: true,
        splitStringsChunkLength: 10,
        stringArray: true,
        stringArrayEncoding: ['rc4'],
        stringArrayIndexShift: true,
        stringArrayRotate: true,
        stringArrayShuffle: true,
        stringArrayWrappersCount: 5,
        stringArrayWrappersChainedCalls: true,
        stringArrayWrappersParametersMaxCount: 5,
        stringArrayWrappersType: 'function',
        stringArrayThreshold: 0.75,
        transformObjectKeys: true,
        unicodeEscapeSequence: false
      }).getObfuscatedCode();
      
      fs.writeFileSync(filePath, obfuscatedCode);
    }
  });
  
  // Repack asar archive
  execSync(`npx asar pack ./app-unpacked ${asarPath}`);
  
  // Clean up
  execSync('rm -rf ./app-unpacked');
  
  console.log('Application obfuscated and packaged successfully');
};
module.exports = {
    appId: 'com.yourcompany.securetodo',
    productName: 'Secure To-Do',
    directories: {
      output: 'dist'
    },
    files: [
      'src/**/*',
      'node_modules/**/*',
      'package.json',
      'main.js',
      'preload.js',
      'target/release/libelectron_secure_module.node'
    ],
    win: {
      target: [
        {
          target: 'nsis',
          arch: ['x64']
        }
      ],
      icon: 'assets/icon.ico',
      signingHashAlgorithms: ['sha256'],
      signAndEditExecutable: true,
      signDlls: true
    },
    nsis: {
      oneClick: false,
      allowToChangeInstallationDirectory: true,
      createDesktopShortcut: true,
      createStartMenuShortcut: true,
      shortcutName: 'Secure To-Do'
    },
    publish: {
      provider: 'github',
      releaseType: 'release'
    }
  };
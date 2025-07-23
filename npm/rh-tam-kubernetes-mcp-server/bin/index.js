#!/usr/bin/env node

const childProcess = require('child_process');
const fs = require('fs');
const path = require('path');

// Map Node.js platform names to Go platform names
const platformMap = {
    'darwin': 'darwin',
    'linux': 'linux',
    'win32': 'windows'
};

// Map Node.js arch names to Go arch names
const archMap = {
    'x64': 'amd64',
    'arm64': 'arm64'
};

const BINARY_MAP = {
    'darwin_x64': {name: 'rh-tam-kubernetes-mcp-server-darwin-amd64', suffix: ''},
    'darwin_arm64': {name: 'rh-tam-kubernetes-mcp-server-darwin-arm64', suffix: ''},
    'linux_x64': {name: 'rh-tam-kubernetes-mcp-server-linux-amd64', suffix: ''},
    'linux_arm64': {name: 'rh-tam-kubernetes-mcp-server-linux-arm64', suffix: ''},
    'win32_x64': {name: 'rh-tam-kubernetes-mcp-server-windows-amd64', suffix: '.exe'},
    'win32_arm64': {name: 'rh-tam-kubernetes-mcp-server-windows-arm64', suffix: '.exe'},
};

// Resolving will fail if the optionalDependency was not installed or the platform/arch is not supported
const resolveBinaryPath = () => {
  try {
    const platform = platformMap[process.platform];
    const arch = archMap[process.arch];
    
    if (!platform || !arch) {
      throw new Error(`Unsupported platform/arch: ${process.platform}/${process.arch}`);
    }

    const binary = BINARY_MAP[`${process.platform}_${process.arch}`];
    if (!binary) {
      throw new Error(`No binary found for platform/arch: ${process.platform}/${process.arch}`);
    }

    // Try local path first
    const localPath = path.join(__dirname, binary.name + binary.suffix);
    if (fs.existsSync(localPath)) {
      return localPath;
    }

    // Try node_modules path
    const nodePath = require.resolve(`${binary.name}/bin/${binary.name}${binary.suffix}`);
    if (fs.existsSync(nodePath)) {
      return nodePath;
    }

    throw new Error(`Binary not found for ${platform}-${arch}`);
  } catch (e) {
    throw new Error(`Could not resolve binary path for platform/arch: ${process.platform}/${process.arch} - ${e.message}`);
  }
};

childProcess.execFileSync(resolveBinaryPath(), process.argv.slice(2), {
  stdio: 'inherit',
});

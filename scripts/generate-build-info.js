#!/usr/bin/env node

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Version and build information
const packageJson = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const version = packageJson.version;

// GitHub Actions environment variables
const isGitHubActions = process.env.GITHUB_ACTIONS === 'true';
const githubRef = process.env.GITHUB_REF || '';
const githubSha = process.env.GITHUB_SHA || '';
const buildTime = process.env.BUILD_TIME || new Date().toISOString();

// Generate package.json with build info
const packageInfo = {
  name: 'net-watcher',
  version: version,
  description: 'Secure network traffic recorder for DNS monitoring',
  author: 'Abbas Jafari',
  license: 'MIT',
  repository: {
    type: 'git',
    url: 'https://github.com/abja/net-watcher.git'
  },
  buildInfo: {
    version: version,
    commitSha: githubSha,
    buildTime: buildTime,
    goVersion: process.env.GO_VERSION || execSync('go version', { encoding: 'utf8' }).toString().trim(),
    isGitHubActions: isGitHubActions,
    branch: githubRef.replace('refs/heads/', '').replace('refs/tags/', '')
  }
};

// Write package.json
fs.writeFileSync('package.json', JSON.stringify(packageInfo, null, 2));

// Generate build info file
const buildInfo = {
  version: version,
  commitSha: githubSha,
  buildTime: buildTime,
  goVersion: execSync('go version', { encoding: 'utf8' }).toString().trim(),
  builder: isGitHubActions ? 'GitHub Actions' : 'Local',
  branch: githubRef.replace('refs/heads/', '').replace('refs/tags/', '')
};

fs.writeFileSync('build-info.json', JSON.stringify(buildInfo, null, 2));

console.log('Generated package.json and build-info.json');
console.log(`Version: ${version}`);
console.log(`Commit: ${githubSha}`);
console.log(`Branch: ${buildInfo.branch}`);
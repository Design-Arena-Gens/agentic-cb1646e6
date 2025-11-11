#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const directories = ['uploads', 'invoices'];
for (const dir of directories) {
  const fullPath = path.join(process.cwd(), dir);
  if (!fs.existsSync(fullPath)) {
    fs.mkdirSync(fullPath, { recursive: true });
  }
}
console.log('Directories verified.');

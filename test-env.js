const dotenv = require('dotenv');
const path = require('path');
const fs = require('fs');

const envPath = path.resolve(__dirname, '.env');
console.log('Checking for .env at:', envPath);

if (fs.existsSync(envPath)) {
  console.log('.env file exists');
  const result = dotenv.config({ path: envPath });
  if (result.error) {
    console.error('Error loading .env:', result.error);
  } else {
    console.log('GOOGLE_CLIENT_ID:', process.env.GOOGLE_CLIENT_ID);
    console.log('GOOGLE_CLIENT_SECRET:', process.env.GOOGLE_CLIENT_SECRET ? 'Loaded' : 'Not set');
  }
} else {
  console.error('.env file does not exist');
}
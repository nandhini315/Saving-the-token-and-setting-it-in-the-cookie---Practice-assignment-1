const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// --- CONFIGURATION ---
const jwtSecret = 'your_jwt_secret'; // This is your JWT secret key
const encryptionKey = crypto.randomBytes(32); // 256-bit key
const iv = crypto.randomBytes(16); // Initialization vector

// --- Step 1: Create a JWT Token ---
const payload = {
  userId: 1,
  username: 'john_doe',
};
const token = jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
console.log('Original JWT Token:', token);

// --- Step 2: Encrypt the JWT Token ---
function encryptToken(token) {
  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return {
    encryptedToken: encrypted,
    iv: iv.toString('hex'), // send this with the token
  };
}

const { encryptedToken, iv: encryptedIV } = encryptToken(token);
console.log('\nEncrypted Token:', encryptedToken);
console.log('IV:', encryptedIV);

// --- Step 3: Decrypt the JWT Token ---
function decryptToken(encryptedToken, ivHex) {
  const ivBuffer = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivBuffer);
  let decrypted = decipher.update(encryptedToken, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

const decryptedJWT = decryptToken(encryptedToken, encryptedIV);
console.log('\nDecrypted JWT:', decryptedJWT);

// --- Step 4: Verify JWT Token ---
jwt.verify(decryptedJWT, jwtSecret, (err, decoded) => {
  if (err) {
    console.log('\nVerification Failed:', err.message);
  } else {
    console.log('\n✅ Success: JWT Verified:', decoded);
  }
});

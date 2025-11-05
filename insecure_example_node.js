// insecure_example_node.js
// Exemplos Node.js: MD5, AES-ECB, RSA 1024

const crypto = require('crypto');

// MD5 (inseguro)
function md5Sum(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// SHA1 (inseguro)
function sha1Sum(data) {
  return crypto.createHash('sha1').update(data).digest('hex');
}

// AES-128-ECB (inseguro). Node crypto supports 'aes-128-ecb' algorithm name.
function aesEcbEncrypt(key, plaintext) {
  // key: Buffer(16)
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(true);
  let encrypted = cipher.update(plaintext, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return encrypted;
}

// Generate RSA-1024 (insecure)
function generateRsa1024() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024, // <<-- insecure
    publicExponent: 0x10001
  });
  return { publicKey, privateKey };
}

function main() {
  const msg = "segredo-nodejs";

  console.log("MD5:", md5Sum(msg));
  console.log("SHA1:", sha1Sum(msg));

  const hardKey = Buffer.from('0123456789abcdef'); // hardcoded 16B key
  console.log("AES-ECB (base64):", aesEcbEncrypt(hardKey, msg));

  const keys = generateRsa1024();
  console.log("RSA-1024 public key (pem):", keys.publicKey.export({ type: 'pkcs1', format: 'pem' }).split('\n').slice(0,3).join('\\n'));
}

main();

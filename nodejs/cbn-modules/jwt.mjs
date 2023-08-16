const {generateKey,createSign,createVerify,KeyObject,randomBytes,scrypt,randomFill, createCipheriv, createDecipheriv} = await import('node:crypto');
const { subtle } = globalThis.crypto;
import { Buffer } from 'node:buffer';
const headerObject = {
  alg: 'RS256',
  typ: 'JWT',
  kid: 'public'
};
const headerString = JSON.stringify(headerObject);
const encodedHeader = Buffer.from(headerString).toString('base64url');

// JWE ====================================================================

function returnEncodedJWEProtectedHeader(){
  let headerObject = {"alg":"dir","enc":"A256GCM"}; //An empty octet sequence is used as the JWE Encrypted Key value.
  let headerString = JSON.stringify(headerObject);
  let encodedJWEProtectedHeader = Buffer.from(headerString).toString('base64url');
  return encodedJWEProtectedHeader
}
async function issueJWE(contentEncryptionCryptoKey, claimsObject){
  let encodedJWEProtectedHeader = returnEncodedJWEProtectedHeader()
  //encodedJWEProtectedHeader = Buffer.from(encodedJWEProtectedHeader);
  let claimsString = JSON.stringify(claimsObject);
  let claimsBase64URLEncoded = Buffer.from(claimsString).toString('base64url');
  //let claimsBuffer = Buffer.from(claimsBase64URLEncoded);
  let encryptionObject = await returnEncryptedObject(contentEncryptionCryptoKey, encodedJWEProtectedHeader, claimsBase64URLEncoded);
  let iv = Buffer.from(encryptionObject.iv).toString('base64url');
  let cipherText = Buffer.from(encryptionObject.cipherText).toString('base64url');
  let authTag = Buffer.from(encryptionObject.authTag).toString('base64url');
  let encryptedKey = "";
  return encodedJWEProtectedHeader + "." + encryptedKey + "." + iv + "." + cipherText + "." + authTag;
}

function keyGen () {
  return new Promise(function(resolve, reject) {
    // crypto.createSecretKey(key[, encoding]) or
    generateKey('aes', { length: 256 }, (err, key) => {
      if (err) {
        reject (err);
      }
      //console.dir(key)
      //let jwk = key.export({format:'jwk'});
      ///jwk = JSON.stringify(jwk);
      //resolve (jwk);
      resolve (key)
    });
  });
}

function ivGen () {
  return new Promise(function(resolve, reject) {
    //let buf = Buffer.alloc(16); makes 128 bit
    let buf = Buffer.alloc(32); //makes 256 bit
    randomFill(buf, (err, buf) => {
      if (err) reject (err);
      // buf = buf.toString('utf-8');
      // resolve(Buffer.from(buf).toString('base64url'));
      resolve(buf);
    });
  });
}

const key = await keyGen();
const iv = await ivGen();

async function setJWE(claimsObject){
  let headerObject = {"alg":"dir","enc":"A256GCM"}; 
  let headerString = JSON.stringify(headerObject);

  let claimsString = JSON.stringify(claimsObject);
  let claimsBase64URLEncoded = Buffer.from(claimsString).toString('base64url');
  let cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(headerString));
  cipher.setAutoPadding();
  let encrypted = cipher.update(claimsString,'utf8','base64url');
  encrypted += cipher.final('base64url');
  let tag = cipher.getAuthTag().toString('base64url');
  let encryptedKey = "";
  let ivString = Buffer.from(iv).toString('base64url');
  let encodedJWEProtectedHeader = Buffer.from(headerString).toString('base64url');
  let result = encodedJWEProtectedHeader + "." + encryptedKey + "." + ivString + "." + encrypted + "." + tag;
  return result;
}

// async function returnEncryptedObject(contentEncryptionCryptoKey, encodedJWEProtectedHeader, claimsBase64URLEncoded) {
//   let obj = {};
//   let tagLength = 128;
//   //let iv = randomBytes(12);
//   //let iv = crypto.getRandomValues(new Uint8Array(12));
//   let iv = crypto.getRandomValues(new Uint8Array(24));
//   let additionalData = Buffer.from(encodedJWEProtectedHeader, 'base64url');
//   let cipherText = await crypto.subtle.encrypt(
//     {
//       name: "AES-GCM",
//       iv: iv,
//       additionalData: encodedJWEProtectedHeader//, //buffer from ASCII(BASE64URL(UTF8(JWE Protected Header)))
//     },
//     contentEncryptionCryptoKey,
//     claimsBase64URLEncoded
//   );
//   let authTagBytesLength = tagLength / 8;
//   let authTagBytes = cipherText.slice(cipherText.byteLength - authTagBytesLength,cipherText.byteLength);
//   obj.iv = new TextDecoder().decode(iv);
//   obj.cipherText = new TextDecoder().decode(cipherText);
//   obj.authTag = new TextDecoder().decode(authTagBytes);
//   return obj;
// }

async function decryptMessage(jwe) {
  let parts = jwe.split(".");
  let encodedJWEProtectedHeader = parts[0];
  let protectedHeaderBuffer = Buffer.from(encodedJWEProtectedHeader,'base64url');
  let cipherText = parts[3];
  let tag = parts[4];
  let tagBuffer = Buffer.from(tag,'base64url');

  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(protectedHeaderBuffer);
    decipher.setAuthTag(tagBuffer);
    let decrypted = decipher.update(cipherText,'base64url','utf8');
    decrypted += decipher.final('utf8');
    console.log("decrypted is: " + decrypted);
  } catch (e) {
    console.dir(e); 
  }

}

function issue(privateKey,claims){
  let payloadString = JSON.stringify(claims);
  let encodedPayload = Buffer.from(payloadString).toString('base64url');
  const sign = createSign('SHA256');
  sign.write(encodedHeader + '.' + encodedPayload);
  sign.end();
  let signature = sign.sign(privateKey, 'base64url');
  let jsonWebToken = encodedHeader + '.' + encodedPayload + '.' + signature;
  return jsonWebToken;
}

function verify(publicKey,jwt){
  let jwtParts = jwt.split('.');
  let jwtHeader = jwtParts[0];
  let jwtPayload = jwtParts[1];
  let jwtSignature = jwtParts[2];
  let obj = {};
  try {
    let header = JSON.parse(Buffer.from(jwtHeader, 'base64url').toString('utf-8'));
    let alg = header.alg;
    if(alg === "RS256"){ // MUST verify alg is not set to none
      const verify = createVerify('SHA256');
      verify.write(jwtHeader + '.' + jwtPayload);
      verify.end();
      obj.valid = verify.verify(publicKey, jwtSignature, 'base64url');
      obj.payload = {};
      try {
        jwtPayload = JSON.parse(Buffer.from(jwtPayload, 'base64url').toString('utf-8'));
        obj.payload = Object.assign(obj.payload,jwtPayload);
      } finally {
        return obj;
      }
    }
  } finally {
    obj.valid = false;
    return obj;
  }
}

export default {issue, issueJWE, verify, decryptMessage, setJWE};

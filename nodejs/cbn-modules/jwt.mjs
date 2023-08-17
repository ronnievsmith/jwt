const {generateKey,createSign,createVerify,KeyObject,randomBytes,scrypt,randomFill, createCipheriv, createDecipheriv,createSecretKey} = await import('node:crypto');
const { subtle } = globalThis.crypto;
import { Buffer } from 'node:buffer';
const headerObject = {
  alg: 'RS256',
  typ: 'JWT',
  kid: 'public'
};
const headerString = JSON.stringify(headerObject);
const encodedHeader = Buffer.from(headerString).toString('base64url');

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

async function setJWE(claimsObject){
  let headerObject = {"alg":"dir","enc":"A256GCM"}; 
  let headerString = JSON.stringify(headerObject);
  let iv = await ivGen();
  let key = Buffer.from(process.env.jwkKey,'base64url');
  let claimsString = JSON.stringify(claimsObject);
  let claimsBase64URLEncoded = Buffer.from(claimsString).toString('base64url');

  //console.dir(key)
  //console.log("key size is " + key.symmetricKeySize + " and type is " + key.type)
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

async function decryptMessage(jwe) {
  let parts = jwe.split(".");
  let encodedJWEProtectedHeader = parts[0];
  let protectedHeaderBuffer = Buffer.from(encodedJWEProtectedHeader,'base64url');
  let cipherText = parts[3];
  let tag = parts[4];
  let tagBuffer = Buffer.from(tag,'base64url');
  console.log(process.env.jwkKey)
  let key = Buffer.from(process.env.jwkKey,'base64url');
  let iv = Buffer.from(parts[2],'base64url');
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

function issue(claims){
  let payloadString = JSON.stringify(claims);
  let encodedPayload = Buffer.from(payloadString).toString('base64url');
  const sign = createSign('SHA256');
  sign.write(encodedHeader + '.' + encodedPayload);
  sign.end();
  let signature = sign.sign(process.env.jwsPrivateKey, 'base64url');
  let jsonWebToken = encodedHeader + '.' + encodedPayload + '.' + signature;
  return jsonWebToken;
}

function verify(jwt){
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
      obj.valid = verify.verify(process.env.jwsPublicKey, jwtSignature, 'base64url');
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

export default {issue, verify, decryptMessage, setJWE};

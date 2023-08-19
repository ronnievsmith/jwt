import { Buffer } from 'node:buffer';
import fs from "node:fs";
import url from 'node:url';
import path from "node:path";
const {
  createCipheriv,
  createDecipheriv,
  createSign,
  createVerify,
  createPrivateKey,
  createPublicKey,
  createSecretKey,
  randomFill,
  generateKey,
  generateKeyPairSync,
  randomUUID,
} = await import('node:crypto');
const DIR_NAME = path.dirname(url.fileURLToPath(import.meta.url));
const APP_PATH = path.join(DIR_NAME, '.');
const KEY_PATH = path.join(APP_PATH, 'keys');
const JWS_KEY_PATH = path.join(APP_PATH, 'keys', 'jws');
const JWE_KEY_PATH = path.join(APP_PATH, 'keys', 'jwe');
const JWS_PRIVATE_KEY_PATH = path.join(JWS_KEY_PATH, 'private.pem');
const JWS_PUBLIC_KEY_PATH = path.join(JWS_KEY_PATH, 'public.pem');  
const JWE_JWK_PATH = path.join(APP_PATH, 'keys', 'jwe', 'jwk.json');
const DAY_IN_MILLISECONDS = 86400000;
const WEEK_IN_MILLISECONDS = 604800000;
const MONTH_IN_MILLISECONDS = 2629800000;
var JWS_PRIVATE_KEY;
var JWS_PUBLIC_KEY;
var JWE_JWK;

async function issue(request,response,type){
  let exp = Date.now() + MONTH_IN_MILLISECONDS;
  let claimsObject = {
    "exp":exp,
    "iss":"nodejs",
    "roles":["member","admin"],
    "sub":randomUUID(),
    "email":"joe@blow.com"
  };
  let cookie = undefined;
  let cookieArray = [];
  try {
    if(type === "jws"){
      cookie = returnJWS(claimsObject);
    }
    if(type === "jwe"){
      cookie = await returnJWE(claimsObject);
    }
  } finally {
    if(cookie){
      //cookieArray.push(`token=${cookie}; HttpOnly; Secure`);
      cookieArray.push(`token=${cookie}`);
      //cookieArray.push(`i-am-another-cookie=true`);
      response.setHeader('Set-Cookie', cookieArray);
    }
    response.end(); 
  }
}

async function decryptJWE(jwe) {
  let parts = jwe.split(".");
  let encodedJWEProtectedHeader = parts[0];
  let protectedHeaderBuffer = Buffer.from(encodedJWEProtectedHeader,'base64url');
  let cipherText = parts[3];
  let tag = parts[4];
  let tagBuffer = Buffer.from(tag,'base64url');
  let iv = Buffer.from(parts[2],'base64url');
  try {
    const decipher = createDecipheriv('aes-256-gcm', JWE_JWK, iv);
    decipher.setAAD(protectedHeaderBuffer);
    decipher.setAuthTag(tagBuffer);
    let decrypted = decipher.update(cipherText,'base64url','utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
  } catch (e) {
    console.dir(e);
    return null;
  }
}

async function loadKeys() {
  try {
    let privateKey = fs.readFileSync(JWS_PRIVATE_KEY_PATH, 'utf8');
    let publicKey = fs.readFileSync(JWS_PUBLIC_KEY_PATH, 'utf8');
    JWS_PRIVATE_KEY = await generatePrivateKey (privateKey);
    JWS_PUBLIC_KEY = await generatePublicKey (publicKey);
    console.log('\x1b[32m%s\x1b[0m',`Loaded assymetric keys from ${JWS_PUBLIC_KEY_PATH}, and ${JWS_PRIVATE_KEY_PATH}`);
  } catch (e) {
    console.log("loadKeys JWS catch fired w error: " + e);
    let { privateKey, publicKey } = generateKeyPairSync("rsa", { //public key file NOT found
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem',
      }
    });
    if(!fs.existsSync(KEY_PATH)){
      fs.mkdirSync(KEY_PATH);
    }
    if (!fs.existsSync(JWS_KEY_PATH)){
      fs.mkdirSync(JWS_KEY_PATH);
    }
    fs.writeFileSync(JWS_PRIVATE_KEY_PATH, privateKey);
    fs.writeFileSync(JWS_PUBLIC_KEY_PATH, publicKey);
    JWS_PRIVATE_KEY = await generatePrivateKey (privateKey);
    JWS_PUBLIC_KEY = await generatePublicKey (publicKey);
    console.log('\x1b[32m%s\x1b[0m',`Generated assymetric keys saved to ${JWS_PUBLIC_KEY_PATH}, and ${JWS_PRIVATE_KEY_PATH}`);
  }

  try {
    let jwkString = fs.readFileSync(JWE_JWK_PATH, 'utf8');
    let jwkObject = JSON.parse(jwkString);
    console.log('\x1b[32m%s\x1b[0m',`Loaded JWK from ${JWE_JWK_PATH}.`);
    JWE_JWK = createSecretKey(jwkObject.k,'base64url');
  } catch (e) {
    JWE_JWK = await generateSecretKey();
    let jwk = JWE_JWK.export({format:'jwk'});
    if(!fs.existsSync(KEY_PATH)){
      fs.mkdirSync(KEY_PATH);
    }
    if (!fs.existsSync(JWE_KEY_PATH)){
      fs.mkdirSync(JWE_KEY_PATH);
    }
    fs.writeFileSync(JWE_JWK_PATH, JSON.stringify(jwk));
    console.log('\x1b[32m%s\x1b[0m',`Generated JWK and saved as ${JWE_JWK_PATH}`);
  }
  return;
}

function generateInitializationVector () {
  return new Promise(function(resolve, reject) {
    let buf = Buffer.alloc(32); //makes 256 bit
    randomFill(buf, (err, buf) => {
      if (err) reject (err);
      resolve(buf);
    });
  });
}

async function returnJWE(claimsObject){
  let headerObject = {"alg":"dir","enc":"A256GCM"}; 
  let headerString = JSON.stringify(headerObject);
  let iv = await generateInitializationVector();
  let claimsString = JSON.stringify(claimsObject);
  let claimsBase64URLEncoded = Buffer.from(claimsString).toString('base64url');
  let cipher = createCipheriv('aes-256-gcm', JWE_JWK, iv);
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

function returnJWS(claims){
  let headerObject = {
    alg: 'RS256',
    typ: 'JWT',
    kid: 'public'
  };
  let headerString = JSON.stringify(headerObject);
  let encodedHeader = Buffer.from(headerString).toString('base64url');
  let payloadString = JSON.stringify(claims);
  let encodedPayload = Buffer.from(payloadString).toString('base64url');
  const sign = createSign('SHA256');
  sign.write(encodedHeader + '.' + encodedPayload);
  sign.end();
  let signature = sign.sign(JWS_PRIVATE_KEY, 'base64url');
  let jsonWebToken = encodedHeader + '.' + encodedPayload + '.' + signature;
  return jsonWebToken;
}

function validateJWS(jwt){
  let jwtParts = jwt.split('.');
  let jwtHeader = jwtParts[0];
  let jwtPayload = jwtParts[1];
  let jwtSignature = jwtParts[2];
  let valid = false;
  try {
    let header = JSON.parse(Buffer.from(jwtHeader, 'base64url').toString('utf-8'));
    let alg = header.alg;
    if(alg === "RS256"){ // MUST verify alg is not set to none
      let verify = createVerify('SHA256');
      verify.write(jwtHeader + '.' + jwtPayload);
      verify.end();
      valid = verify.verify(JWS_PUBLIC_KEY, jwtSignature, 'base64url');
      if(valid){
        return JSON.parse(Buffer.from(jwtPayload, 'base64url').toString('utf-8'));
      } else {
        return null;
      }
    } else {
      return null;      
    }
  } catch (e) {
    console.log (e);
    return null;
  }
}

function generateSecretKey () {
  return new Promise(function(resolve, reject) {
    generateKey('aes', { length: 256 }, (err, key) => {
      if (err) {
        reject (err);
      }
      resolve (key)
    });
  });
}
function generatePrivateKey (str) {
  return new Promise(function(resolve, reject) {
    try {
      let key = createPrivateKey({
          key: str,
          format: 'pem',
          encoding: 'utf-8'
      })
      resolve (key);
    } catch (e) {
      reject (e);
    }
  });
}
function generatePublicKey (str) {
  return new Promise(function(resolve, reject) {
    try {
      let key = createPublicKey({
          key: str,
          format: 'pem',
          encoding: 'utf-8'
      })
      resolve (key);
    } catch (e) {
      reject (e);
    }
  });
}

export default {issue, decryptJWE, loadKeys, returnJWS, returnJWE, validateJWS};

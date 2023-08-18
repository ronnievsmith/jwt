//import db from './db.mjs';
import fs from "node:fs";
import jwt from './jwt.mjs';
const {generateKeyPairSync,randomUUID,generateKey,randomFill,KeyObject,createSecretKey} = await import('node:crypto');
//import sgMail from '@sendgrid/mail';
import url from 'node:url';
import path from "node:path";
import * as readline from 'node:readline/promises';
const DIR_NAME = path.dirname(url.fileURLToPath(import.meta.url));
const APP_PATH = path.join(DIR_NAME, '..');
const ROOT_PATH = path.join(DIR_NAME, '...');
const JWS_KEY_PATH = path.join(APP_PATH, 'keys', 'jws');
const JWE_KEY_PATH = path.join(APP_PATH, 'keys', 'jwe');
const JWS_PRIVATE_KEY_PATH = path.join(JWS_KEY_PATH, 'private.pem');
const JWS_PUBLIC_KEY_PATH = path.join(JWS_KEY_PATH, 'public.pem');	
const JWE_JWK_PATH = path.join(APP_PATH, 'keys', 'jwe', 'jwk.json');
//const JWE_INITIALIZATION_VECTOR_PATH = path.join(JWE_KEY_PATH, 'kek.json');
const DAY = 86400000;
const WEEK = 604800000;
const MONTH = 2629800000;
//const jwtKeysObject = getKeys('jwt');
//const jweKeysObject = getKeys('jwe');



async function accessToken(request,response,type){
  let oneMonth = 2629800000;
  let exp = Date.now() + oneMonth;
  let claimsObject = {
    "exp":exp,
    "iss":"nodejs",
    "roles":["member","admin"],
    "sub":randomUUID(),
    "email":"joe@blow.com"
  };
  let cookie = undefined;

	try {
		if(type === "jws"){
		  cookie = jwt.issue(claimsObject);

		}
		if(type === "jwe"){
			cookie = await jwt.setJWE(claimsObject);
			
		}

	} finally {
	  let cookieArray = [];
	  //cookieArray.push(`i-am-a-cookie=true`);
	  //cookieArray.push(`token=${cookie}; HttpOnly; Secure`);
	  cookieArray.push(`token=${cookie}`);
	  response.setHeader('Set-Cookie', cookieArray);
		response.end();	
	}
}

function keyGen () {
  return new Promise(function(resolve, reject) {
    // crypto.createSecretKey(key[, encoding]) or
    generateKey('aes', { length: 256 }, (err, key) => {
      if (err) {
        reject (err);
      }
      resolve (key)
    });
  });
}

async function getKeys() {
  try {
	  process.env.jwsPrivateKey = fs.readFileSync(JWS_PRIVATE_KEY_PATH, 'utf8');
	  process.env.jwsPublicKey = fs.readFileSync(JWS_PUBLIC_KEY_PATH, 'utf8');
  } catch {
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

	  process.env.jwsPrivateKey = privateKey;
	  process.env.jwsPublicKey = publicKey;
    if (!fs.existsSync(JWS_KEY_PATH)){
		  fs.mkdirSync(JWS_KEY_PATH);
		}
		fs.writeFileSync(JWS_PRIVATE_KEY_PATH, privateKey);
    fs.writeFileSync(JWS_PUBLIC_KEY_PATH, publicKey);
  }

  try {
  	let jwkString = fs.readFileSync(JWE_JWK_PATH, 'utf8');
  	let jwkObject = JSON.parse(jwkString);
	  process.env.jwkKey = jwkObject.k;
	  process.env.jwkString = jwkString;
	  //process.env.keyObject = KeyObject.from(jwkString)
	  //createSecretKey(key[, encoding])
	  //let keyObject = createSecretKey(jwkString,'base64url');
	  //process.env.keyObject = keyObject
	  //console.log("type is: " + keyObject.symmetricKeySize)
	  return
  } catch (e){
  	console.log("getKey catch fired" + e)
  	let keyObject = await keyGen();
  	
  	let jwk = keyObject.export({format:'jwk'})
  	process.env.jwkString = JSON.stringify(jwk);
		process.env.jwkKey = jwk.k;

	  if (!fs.existsSync(JWE_KEY_PATH)){
		  fs.mkdirSync(JWE_KEY_PATH);
		}
		fs.writeFileSync(JWE_JWK_PATH, JSON.stringify(jwk));
  }
  return;
}

export default {getKeys,accessToken};
//import db from './db.mjs';
import fs from "node:fs";
import jwt from './jwt.mjs';
const {generateKeyPairSync,randomUUID} = await import('node:crypto');
//import sgMail from '@sendgrid/mail';
import url from 'node:url';
import path from "node:path";
import * as readline from 'node:readline/promises';
const DIR_NAME = path.dirname(url.fileURLToPath(import.meta.url));
const APP_PATH = path.join(DIR_NAME, '..');
const KEYS_PATH = path.join(APP_PATH, 'keys');
const JWS_KEYS_PATH = path.join(KEYS_PATH, 'jws');
const JWE_KEYS_PATH = path.join(KEYS_PATH, 'jwe');
const ROOT_PATH = path.join(DIR_NAME, '...');
const JWS_PRIVATE_KEY_PATH = path.join(APP_PATH, 'keys', 'jws', 'private.pem');
const JWS_PUBLIC_KEY_PATH = path.join(APP_PATH, 'keys', 'jws', 'public.pem');
const JWE_CEK_KEY_PATH = path.join(APP_PATH, 'keys', 'jwe', 'jwk.json');
const JWE_KEK_KEY_PATH = path.join(JWE_KEYS_PATH, 'kek.json');
const JWE_PRIVATE_KEY_PATH = path.join(JWE_KEYS_PATH, 'private.pem');
const JWE_PUBLIC_KEY_PATH = path.join(JWE_KEYS_PATH, 'public.pem');
const DAY = 86400000;
const WEEK = 604800000;
const MONTH = 2629800000;
const jwtKeysObject = getKeys('jwt');
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
		  cookie = jwt.issue(jwtKeysObject.privateKey, claimsObject);

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



async function getKeys() {
//async function getKeys(arg) {
	let obj = {};
	obj.jws = {};
	//if(arg === "jwt"){
	  //if (fs.existsSync(JWT_PUBLIC_KEY_PATH)) { //public key file found on disk
	  try {
		  obj.jws.privateKey = fs.readFileSync(JWS_PATH, 'utf8');
		  obj.jws.publicKey = fs.readFileSync(JWS_PATH, 'utf8');
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
		  obj.jws.privateKey = privateKey;
		  obj.jws.publicKey = publicKey;
	    if (!fs.existsSync(JWS_PATH)){
			  fs.mkdirSync(JWS_PATH);
			}
			fs.writeFileSync(JWS_PATH, privateKey);
	    fs.writeFileSync(JWS_PATH, publicKey);
	  }
	  try {
		  obj.jwe.symmetricKey = fs.readFileSync(JWE_PATH, 'utf8');
		  obj.jwe.initializationVector = fs.readFileSync(JWE_PATH, 'utf8');
	  } catch {

			let contentEncryptionCryptoKey = await returnCEK();
			obj.contentEncryptionCryptoKey = contentEncryptionCryptoKey;


		  if (!fs.existsSync(JWE_PATH)){
			  fs.mkdirSync(JWE_PATH);
			}
			fs.writeFileSync(JWE_PATH, privateKey);
	    fs.writeFileSync(JWE_PATH, publicKey);
	  }

	//} eparlana
	//if(arg === "jwe"){

	//}
}

export default {getKeys,accessToken};
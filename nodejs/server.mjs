/*
  Ronnie Royston (https://ronnieroyston.com)
*/

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import url from 'node:url';
import 'dotenv/config';
const DIR_NAME = path.dirname(url.fileURLToPath(import.meta.url));
import jwt from './cbn-modules/jwt.mjs';
import authentication from './cbn-modules/authentication.mjs';
const PORT = process.env.NODEJS_PORT || 8080;
const ROOT_DIRECTORY = './public';
const ROOT_PATH = path.join(DIR_NAME, ROOT_DIRECTORY);
var keys = undefined;

// const { privateKey, publicKey } = authentication.getKeys("jwt");  //before we start server we need RSA keys

const SERVER = http.createServer(async function(request, response) {

  let sub = await user(request);
  //console.dir(sub)

  if (request.url.startsWith('/auth')){ // ================================================
    let type = request.url.split("?")[1];
    await authentication.accessToken(request,response,type);
    return response.end();
  } else if (request.url === '/logout'){
    if(request.headers.cookie){
      let cookies = request.headers.cookie.split(";");
      let cookieArray = [];
      cookies.forEach(function(cookie){
        let key = cookie.split("=")[0];
        cookieArray.push(`${key}=null; max-age=0`)
      })
      response.setHeader('Set-Cookie', cookieArray);
      return response.end();
    }
  } else { // =====================================================================================
    let indexPath = path.join(ROOT_PATH,'index.html');
    let stat = fs.statSync(indexPath);
    response.writeHead(200, {
        'Content-Type': 'text/html',
        'Content-Length': stat.size,
        'Access-Control-Allow-Origin': '*',
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
    });
    let readStream = fs.createReadStream(indexPath);
    return readStream.pipe(response);
  }
});

(async function () {
    try {
      await authentication.getKeys();  //before we start server we need RSA keys
      await SERVER.listen(PORT);
      console.log('\x1b[32m%s\x1b[0m',`Server running at http://127.0.0.1:${PORT}/`);
    } catch(e) {
      console.log('\x1b[31m%s\x1b[0m',`Server failed to start. ${e}`);
    }
})();

function parseCookies(cookie){
  if (cookie){
    cookie = cookie.split("; ");
    let obj = {};
    cookie.forEach((item,index) => {
      let i = item.split("=");
      obj[i[0]]=i[1];
    });
    return obj;   
  }
  return cookie;
}

async function user (request){
  let user = {};
  if(request.headers.cookie){
    try {
      let cookies = parseCookies(request.headers.cookie);
      if(cookies.token){
        let token = cookies.token;
        let tokenParts = token.split('.');
        let jot = undefined;
        console.log("jwt parts array length is " + tokenParts.length)
        if(tokenParts.length > 3){
          jot = await jwt.decryptMessage(token);
        } else {
          jot = jwt.verify(token);
        }
        user = Object.assign(user,jot)   
      }     
    } catch (e) {
      var ip = request.headers['x-forwarded-for'] || request.socket.remoteAddress || null;
      console.log("Error reading authentication from " + ip + e);
    } finally {
      return user;
    }
  }
  return user;
}
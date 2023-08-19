/*
  Ronnie Royston (https://ronnieroyston.com)
*/

import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import url from 'node:url';
import 'dotenv/config';
const DIR_NAME = path.dirname(url.fileURLToPath(import.meta.url));
import jwt from './jwt.mjs';
const PORT = process.env.NODEJS_PORT || 8080;
const ROOT_DIRECTORY = './public';
const ROOT_PATH = path.join(DIR_NAME, ROOT_DIRECTORY);
const SERVER = http.createServer(async function(request, response) {

  let sub = await user(request);
  console.dir(sub);

  if (request.url.startsWith('/auth')){
    let type = request.url.split("?")[1];
    await jwt.issue(request,response,type);
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
  } else {
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
      await jwt.loadKeys();  //before we start server load keys
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
  let user = null;
  try {
    let cookies = parseCookies(request.headers.cookie);
    if(cookies.token){
      let token = cookies.token;
      let tokenParts = token.split('.');
      let jot = undefined;
      if(tokenParts.length === 5){
        user = await jwt.decryptJWE(token);
      } else if (tokenParts.length === 3) {
        user = jwt.validateJWS(token);
      }
    }
  } finally {
    return user;
  }
}
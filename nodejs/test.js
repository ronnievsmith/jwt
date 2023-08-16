// // Asynchronous
const {
  randomBytes,getCiphers,getCipherInfo,subtle
} = await import('node:crypto');

// randomBytes(32, (err, buf) => {
//   if (err) throw err;
//   let output = buf.toString('base64URL');
//   //console.log(output[0]+output[1]+output[2]+"-"+output[3]+output[4]+output[5]+"-"+output[6]+output[7]+output[8]+output[9])
//   console.log(output)
// });
// generateKey()
// async function generateKey(){
//   let key = await crypto.subtle.generateKey(
//     {
//         name: "AES-GCM",
//         length: 256,
//     },
//     true,
//     ["encrypt", "decrypt"]
//   )
//   console.dir(key)
//   return key;
// }

//console.dir(generateKey())

// const {
//   subtle,
// } = await import('node:crypto');

//console.dir(getCiphers());       // aes128-wrap    and  aes-128-cbc-hmac-sha256   are the ciphers
console.dir(getCiphers(), {'maxArrayLength': null})
// console.log(getCipherInfo('id-aes128-wrap'))
// console.log(getCipherInfo('aes128-wrap'))

// const encoder = new TextEncoder();
// const view = encoder.encode("€");
// console.log(view); // Uint8Array(3) [226, 130, 172]

  // crypto.subtle.generateKey(
  //   {
  //   name: "RSA",
  //   // Consider using a 4096-bit key for systems that require long-term security
  //   modulusLength: 2048,
  //   publicExponent: new Uint8Array([1, 0, 1]),
  //   hash: "SHA-256",
  //   },
  //   true,
  //   ["encrypt", "decrypt"]
  // ).then((keyPair) => {

  //     console.log(keyPair.publicKey);

  //     console.log(keyPair.privateKey);

  // });
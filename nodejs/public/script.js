var cbn = (function() {
  const cookies = getCookies();
  let pub = {};
  let thisURL = new URL(window.location.href);
  readAuth()
  window.addEventListener("focus", readAuth);


  async function afterAuth() {
    if (pub.user) {
      document.querySelector("#account").textContent = pub.user.email;
      if (document.querySelector("#bucket-section")) { // if buckets section fetch users bucket info
        document.querySelector("#add-file").hidden = false;
        await readBuckets();
      }
    } else {
      document.querySelector("#account").textContent = "Sign In";
      if (document.querySelector("#bucket-section")) {
        document.querySelector("#add-file").hidden = true;
        // document.querySelector("#bucket-output").innerHTML = "Sign in to access bucket."
      }
    }
  }

  function getCookies() {
    let cookie = document.cookie;
    if (cookie) {
      cookie = cookie.split("; ");
      let obj = {};
      cookie.forEach((item, index) => {
        let i = item.split("=");
        obj[i[0]] = i[1];
      });
      return obj;
    }
    return cookie;
  }

  async function readAuth() {
    try {
      pub.user = parseJwt(cookies.token)
    } finally {
      afterAuth();
    }
  }

  function parseJwt (token) {
    try {
      var base64Url = token.split('.')[1];
      var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      var jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      return JSON.parse(jsonPayload);
    } catch {
      return null;
    }
  }

  return pub; // Expose API
}());
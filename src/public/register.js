import { publicKeyCredentialToJSON, fetchJSON, base64toBuffer } from "./lib.js"

let token

document.forms[0].onsubmit = function (e) {
  e.preventDefault()
  fetchJSON("/register", {
    username: this.username.value,
    fullname: this.fullname.value
  })
  .then((body) => {
    body.challenge.challenge = base64toBuffer(body.challenge.challenge)
    body.challenge.user.id = base64toBuffer(body.challenge.user.id)
    token = body.token
    return body
  })
  .then(({ challenge }) => navigator.credentials.create({ publicKey: challenge }))
  .then((creds) => publicKeyCredentialToJSON(creds))
  .then((jsonCreds) => fetchJSON("/register/response", jsonCreds, token))
  .then((body) => body.status === "registered" && alert("🤙 Yeah, you're registered"))

  .catch(console.error)
}

import { publicKeyCredentialToJSON, fetchJSON, base64toBuffer } from "./lib.js"

let token

document.forms[0].addEventListener("submit", function (e) {
  e.preventDefault()
  fetchJSON("/register", {
    username: this.username.value,
    fullname: this.fullname.value
  })
  .then((/** @type {{token, challenge: PublicKeyCredentialCreationOptions}} */ body) => {
    token = body.token
    const { challenge } = body
    challenge.challenge = base64toBuffer(challenge.challenge)
    challenge.user.id = base64toBuffer(challenge.user.id)
    return challenge
  })
  .then((challenge) => navigator.credentials.create({ publicKey: challenge }))
  .then((creds) => publicKeyCredentialToJSON(creds))
  .then((jsonCreds) => fetchJSON("/register/response", jsonCreds, token))
  .then((body) => body.status === "registered" && alert("🤙 Yeah, you're registered"))

  .catch(console.error)
})

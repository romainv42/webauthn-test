import { publicKeyCredentialToJSON, fetchJSON, base64toBuffer } from "./lib.js"

let token

document.forms[0].onsubmit = function (e) {
  e.preventDefault()
  fetchJSON("/login", {
    username: this.username.value
  })
  .then(body => {
    token = body.token
    const { assertion } = body
    assertion.challenge = base64toBuffer(assertion.challenge)
    assertion.allowCredentials = assertion.allowCredentials.map(
      ({ id, ...rest }) => ({ id: base64toBuffer(id), ...rest })
    )
    return navigator.credentials.get({ publicKey: assertion })
  })
  .then((credentials) => fetchJSON("/login/response", publicKeyCredentialToJSON(credentials), token))
  .then((body) => body.verified === true && alert("🤙 Yeah, you're logged in"))

  .catch(console.error)
}

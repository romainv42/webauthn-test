/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return JSON encoded publicKeyCredential
 */
function publicKeyCredentialToJSON(pubKeyCred) {
  if (Array.isArray(pubKeyCred))
    return pubKeyCred.map(publicKeyCredentialToJSON)

  if (pubKeyCred instanceof ArrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(pubKeyCred)))
  }

  if (pubKeyCred instanceof Object) {
    const obj = {}

    for (const key in pubKeyCred)
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key])

    return obj
  }

  return pubKeyCred
}

var base64decode = (str) => atob(str.replace(/[-]/g, "+").replace(/_/g, "/"))

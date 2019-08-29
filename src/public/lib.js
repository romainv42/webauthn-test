/**
 * Converts PublicKeyCredential into serialised JSON
 * @param  {Object} pubKeyCred
 * @return JSON encoded publicKeyCredential
 */
export function publicKeyCredentialToJSON(pubKeyCred) {
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

const base64decode = str => atob(str.replace(/[-]/g, "+").replace(/_/g, "/"))

export const base64toBuffer = str => Uint8Array.from(base64decode(str), c => c.charCodeAt(0))

/** @param {string} url @param {string} [token] */
export function fetchJSON(url, data, token) {
  const body = JSON.stringify(data)
  const headers = { "Content-Type": "application/json" }
  if (token) headers.Authorization = `Bearer ${token}`
  return fetch(url, { method: "POST", headers, body })
  .then(r => {
    if (r.ok) return r.json()
    throw new Error(`HTTP error ${r.status}: ${r.statusText}`)
  })
}

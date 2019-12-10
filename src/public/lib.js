import { parse } from "path"

/** JSON replacer for Buffer serialization to base64url */
function encodeBuffers(_key, value) {
  if (value instanceof ArrayBuffer) return btoa(String.fromCharCode(...new Uint8Array(value)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")
  return value
}

function parsePublicKeyCredential(data) {
  if (data instanceof PublicKeyCredential) {
    return {
      id: data.id,
      rawId: data.rawId,
      response: {
        attestationObject: data.response.attestationObject,
        clientDataJSON: data.response.clientDataJSON
      },
      type: data.type,
    }  
  }
  return data
}

const base64decode = str => atob(str.replace(/-/g, "+").replace(/_/g, "/"))

export const base64toBuffer = str => Uint8Array.from(base64decode(str), c => c.charCodeAt(0))

/** @param {string} url @param {string} [token] */
export function fetchJSON(url, data, token) {
  data = parsePublicKeyCredential(data)
  const body = JSON.stringify(data, encodeBuffers)
  const headers = { "Content-Type": "application/json" }
  if (token) headers.Authorization = `Bearer ${token}`
  return fetch(url, { method: "POST", headers, body })
  .then(r => {
    if (r.ok) return r.json()
    throw new Error(`HTTP error ${r.status}: ${r.statusText}`)
  })
}

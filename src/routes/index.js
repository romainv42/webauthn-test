const base64url = require("base64url").default
const { timingSafeEqual } = require("crypto")
const {
  verifyAuthenticatorAttestationResponse,
  verifyAuthenticatorAssertionResponse,
  generateServerMakeCredRequest,
  generateServerGetAssertion,
} = require("../utils")

const origin = "http://localhost:3000"

const userSchema = {
  body: {
    type: "object",
    properties: {
      username: { type: "string" },
      fullname: { type: "string" }
    },
    required: ["username"]
  }
}

/** @typedef {{challenge: string, user: {id: string}}} Token */

/** @param {import('fastify').FastifyInstance} fastify */
async function webauthnRoutes(fastify) {

  const { users, ObjectID } = fastify.mongo

  fastify.post("/register", {schema: userSchema}, async (req) => {
    const { username, fullname } = req.body

    const exists = await users.findOne({ username, registered: true })
    if (exists) throw new HTTPError("user already exists", 409)

    const newUser = await users.insertOne({
      username,
      fullname,
      registered: false,
      authenticators: [],
      registrationStart: Date.now
    })
    // I can't find why the MongoDB devs don't expose the id property in the ObjectId typings,
    // but this is the internal buffer used by the ObjectId so it lets us avoid unnecessary string conversion
    // @ts-ignore
    const userId = newUser.insertedId.id

    const challenge = generateServerMakeCredRequest(username, fullname, userId)

    const token = fastify.jwt.sign(challenge)
    return {
      token,
      challenge,
    }
  })

  fastify.post("/register/response", async (req) => {
    /** @type {Token} */ const token = await req.jwtVerify()
    const webauthnResponse = req.body.response
    const clientData = JSON.parse(base64url.decode(webauthnResponse.clientDataJSON))

    if (!timingSafeEqual(base64url.toBuffer(clientData.challenge), base64url.toBuffer(token.challenge)))
      throw new HTTPError("Bad challenge", 401)

    if (clientData.origin !== origin) throw new HTTPError("Bad origin", 403)

    const { verified, authrInfo } = verifyAuthenticatorAttestationResponse(webauthnResponse)

    if (!verified) throw new Error("something wrong happened")

    // @ts-ignore
    const user = await users.findOne({ _id: new ObjectID(base64url.toBuffer(token.user.id)) })

    if (!user) throw new NotFoundError("User doesn't exists in DB")

    user.registered = true
    user.authenticators.push(authrInfo)

    await users.save(user)

    return { status: "registered" }
  })

  fastify.post("/login", {schema: userSchema}, async (req) => {
    const { username } = req.body

    const user = await users.findOne({ username, registered: true })
    if (!user) throw new NotFoundError("User doesn't exists")

    const { authenticators, ...userInfo } = user

    const assertion = generateServerGetAssertion(authenticators)

    const token = fastify.jwt.sign({ assertion, user: userInfo })

    return { token, assertion }
  })

  fastify.post("/login/response", async (req) => {
    /** @type {Token} */ const token = await req.jwtVerify()
    const { response, id } = req.body

    // @ts-ignore
    const user = await users.findOne({ _id: new ObjectID(base64url.toBuffer(token.user.id)), registered: true })
    if (!user) throw new NotFoundError("User doesn't exists in DB")

    const verified = await verifyAuthenticatorAssertionResponse(response, id, user.authenticators)
    if (verified) users.save(user) // the verification method mutated the user's authenticator in-place
    return { verified }
  })
}

module.exports = webauthnRoutes

class HTTPError extends Error {
  constructor(message, status = 500) {
    super(message)
    this.statusCode = status
  }
}
class NotFoundError extends HTTPError {
  constructor(message) {
    super(message, 404)
  }
}

const crypto = require("crypto");

const {
  verifyAuthenticatorAttestationResponse,
  verifyAuthenticatorAssertionResponse,
  generateServerMakeCredRequest,
  generateServerGetAssertion,
} = require("../utils");

const origin = "http://localhost:3000";

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

/** @param {import('fastify').FastifyInstance} fastify */
async function webauthnRoutes(fastify) {

  const { db, ObjectID } = fastify.mongo

  fastify.post("/register", {schema: userSchema}, async (req) => {
    const { username, fullname } = req.body

    const exists = await db.collection("users").findOne({ username, registered: true });
    if (exists) {
      return res.status(409).send("user already exists");
    }

    const newUser = await db.collection("users").insertOne({
      username,
      fullname,
      registered: false,
      authenticators: [],
      registrationStart: Date.now
    })

    const challenge = generateServerMakeCredRequest(username, fullname, newUser.insertedId.toString());

    const token = fastify.jwt.sign(challenge);
    return {
      token,
      challenge,
    }
  });

  fastify.post("/register/response", async (req, res) => {
    const token = await req.jwtVerify()
    const webauthnResponse = req.body;
    const clientData = JSON.parse(Buffer.from(webauthnResponse.response.clientDataJSON, "base64").toString("utf8"))
    clientData.challenge = clientData.challenge.replace(/_/g, "/").replace(/-/g, "+")

    if (Buffer.from(clientData.challenge, "base64").compare(Buffer.from(token.challenge, "base64"))) {
      throw new Error("Bad challenge")
    }

    if (clientData.origin !== origin) {
      throw new Error("Bad origin")
    }

    const result = verifyAuthenticatorAttestationResponse(webauthnResponse)

    if (!result.verified) {
      throw "something wrong happened"
    }

    const user = await db.collection("users").findOne({ _id: ObjectID(token.user.id) })

    if (!user) {
      throw "User doesn't exists in DB"
    }

    user.registered = true;
    user.authenticators.push(result.authrInfo)

    await db.collection("users").save(user);

    return { status: "registered" };
  });

  fastify.post("/login", async (req, res) => {
    if (!req.body || !req.body.username) {
      return res.status(400).end();
    }

    const { username } = req.body;
    const user = await db.collection("users").findOne({ username, registered: true });

    if (!user) {
      throw "User doesn't exists"
    }

    const { authenticators, ...userInfo } = user

    const assertion = generateServerGetAssertion(authenticators)
    assertion.status = "ok"

    const token = fastify.jwt.sign({ assertion, user: userInfo });

    return { token, assertion }
  });

  fastify.post("/login/response", async (req, res) => {
    const token = await req.jwtVerify()
    const webauthnResponse = req.body;

    const user = await db.collection("users").findOne({ _id: ObjectID(token.user._id), registered: true })

    if (!user) {
      throw "User doesn't exists in DB"
    }

    return verifyAuthenticatorAssertionResponse(webauthnResponse, user.authenticators)
  });
}

module.exports = webauthnRoutes;

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

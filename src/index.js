const { readFileSync } = require("fs")
const path = require("path")

// Overwrite the JSON stringifier of Buffers to use base64url.
// That way, we can manipulate raw buffers until the last moment
const { encode } = require('base64url').default
Object.defineProperty(Buffer.prototype, "toJSON", {
    value() { return encode(this) }
})

// Require the framework and instantiate it
const fastify = require("fastify")({
    logger: true
})

const {
    MONGO_USER,
    MONGO_PASSWORD,
    MONGO_DATABASE,
    MONGO_SERVER,
} = process.env


fastify.register(require("fastify-static"), {
    root: path.join(__dirname, "public"),
    prefix: "/public/", // optional: default "/"
})

fastify.register(require("./utils/dbconnector"), {
    url: `mongodb://${MONGO_USER}:${MONGO_PASSWORD}@${MONGO_SERVER}:27017/`,
    dbname: MONGO_DATABASE,
    useNewUrlParser: true
})

fastify.register(require("fastify-jwt"), {
    secret: {
        private: readFileSync(`${path.join(__dirname, "private")}/secret.key`, "utf8"),
        public: readFileSync(`${path.join(__dirname, "private")}/public.key`, "utf8"),
    },
    sign: { algorithm: "ES256" }
})

fastify.register(require("./routes"))

// Run the server!
fastify.listen(3000, "0.0.0.0")
.then(address => fastify.log.info(`server listening on ${address}`))
.catch(err => {
    fastify.log.error(err)
    process.exit(1)
})

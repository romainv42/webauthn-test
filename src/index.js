const { readFileSync } = require("fs")
const path = require("path")

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
})

const jwt = require("fastify-jwt")
fastify.register(jwt, {
    secret: {
        private: readFileSync(`${path.join(__dirname, "private")}/secret.key`, "utf8"),
        public: readFileSync(`${path.join(__dirname, "private")}/public.key`, "utf8"),
    },
    sign: { algorithm: "ES256" }
})

const routes = require("./routes");
fastify.register(routes);

// Run the server!
fastify.listen(3000, "0.0.0.0", function (err, address) {
    if (err) {
        fastify.log.error(err)
        process.exit(1)
    }
    fastify.log.info(`server listening on ${address}`)
})

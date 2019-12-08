const fastifyPlugin = require('fastify-plugin')
const { MongoClient, ObjectID } = require('mongodb')

async function dbConnector(fastify, { url, dbname, ...options }) {
  const co = await MongoClient.connect(url, options)

  const db = co.db(dbname)

  const users = await db.collection("users") || await db.createCollection("users")

  fastify.decorate('mongo', { users, ObjectID })
}

// Wrapping a plugin function with fastify-plugin exposes the decorators,
// hooks, and middlewares declared inside the plugin to the parent scope.
module.exports = fastifyPlugin(dbConnector, { name: "userDb" })

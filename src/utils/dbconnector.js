const fastifyPlugin = require('fastify-plugin')
const { MongoClient, ObjectID } = require('mongodb')

async function dbConnector(fastify, { url, dbname, ...options }) {
  const co = await MongoClient.connect(url, options)

  const db = co.db(dbname)

  const collectionExists = await db.collection("users")

  if (!collectionExists) {
    await db.createCollection("users")
  }

  fastify.decorate('mongo', { db, ObjectID })
}

// Wrapping a plugin function with fastify-plugin exposes the decorators,
// hooks, and middlewares declared inside the plugin to the parent scope.
module.exports = fastifyPlugin(dbConnector)
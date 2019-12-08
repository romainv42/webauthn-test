import * as fastify from 'fastify'
import { MongoClientOptions, Binary, ObjectID, Collection } from 'mongodb'
import { Server, IncomingMessage, ServerResponse } from 'http'

export type Authenticator = {
  fmt: 'fido-u2f'
  publicKey: string
  counter: number
  credID: string
}

export type User = {
  username: string
  fullname: string
  registered: boolean
  authenticators: Authenticator[]
  registrationStart
}


declare const dbConnector: fastify.Plugin<Server, IncomingMessage, ServerResponse,
  {url: string, dbname: string } & MongoClientOptions>
export = dbConnector

declare module 'fastify' {
  interface FastifyInstance {
    mongo: {
      users: Collection<User>,
      ObjectID: typeof ObjectID
    };
  }
}
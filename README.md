# Just a Webauthn Test

Inspired by https://slides.com/fidoalliance/jan-2018-fido-seminar-webauthn-tutorial#/


## Commands

To launch solution:
`make up` 

This will create a MongoDB server, Mongo-express and this NodeJS app.

⚠️In some case, app will be launched before MongoDB is ready to receive connection.
NodeJS App will crash in this case. Wait for some seconds and re-run the same command or
`make start`

App Endpoint: http://localhost:3000
Mongo-Express: http://localhost:8081


To clean:
`make down`


If you made some changes, launch `make build` and `make up` to see your updates.

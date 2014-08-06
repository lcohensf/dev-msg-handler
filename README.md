# dev-msg-handler

This node.js application is part of a Salesforce1 Labs "internet of things" app which consists of 
three components: Force.com app (UI), Qualcomm 2net platform for fitness and wellness device registration notification of device measurements, 
and this node.js application designed for deployment to Heroku. This node.js app processes Qualcomm 2net device notifications
and inserts resulting device measurements into corresponding Force.com org.

See document (2Net Fitness app setup.pdf) for one time setup of Force.com app which includes connected app setup to enable communications with this Heroku node.js app
and information on how to obtain a Qualcomm 2net API key and secret pair.

### Deploying to Heroku

First generate a public key/private key pair for postgres encryption at rest. The demo app uses keys generated with RSA algorithm, length 2048. Do
not set a passphrase for key pair.

### In directory where you clone this repository:

Create heroku app:
heroku create

Create postgres database on heroku:
heroku addons:add heroku-postgresql:dev

Add pgcrypto extension to postgres database:
heroku pg:psql --app your_heroku_app_name
create extension pgcrypto;
\q

Set environment variables on heroku:

heroku config:set CLIENT_ID=YOUR_SALESFORCE_CONNECTED_APP_KEY
heroku config:set CLIENT_SECRET=YOUR_SALESFORCE_CONNECTED_APP_SECRET
heroku config:set CLIENT_ORG_ID=YOUR_SALESFORCE_ORG_ID
heroku config:set REDIRECT_URI=https://your_heroku_app_name.herokuapp.com/oauth/_callback

heroku config:set DATABASE_URL=YOUR_POSTGRES_DATABASE_URL_ON_HEROKU

heroku config:set QCKey=YOUR_QUALCOMM_KEY
heroku config:set QCSecret=YOUR_QUALCOMM_SECRET
heroku config:set QCEndpoint=https://twonetcom.qualcomm.com/kernel/
heroku config:set JWTSecret=YOUR_JWT_TOKEN_SALT_STRING

heroku config:set PUBKey='insert full pubkey string here'
heroku config:set PRIVKey='insert full privkey string here'

Push the app to heroku:

git push heroku master


### Demo on Heroku

This application is running on heroku at: http://dev2netlab.herokuapp.com or https://dev2netlab.herokuapp.com

### Optional worker process

This repository includes a sample worker process implemented in dbutils.js. dbutils.js could be modified to perform maintenance tasks such as purging dated 
Qualcomm notification records from the postgres database -- this is left as an exercise. The app currently writes the number of notification records to the 
system log and is intended to be scheduled via the heroku scheduler add on. Remove the following line from Procfile if you do not want to run this 
sample worker process:

worker: node dbutils.js
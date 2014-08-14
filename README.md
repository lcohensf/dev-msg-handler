# dev-msg-handler

This node.js application is part of a Salesforce1 Labs "internet of things" app which consists of 
three components: Force.com 2Net Fitness app, Qualcomm 2net platform, and this node.js application designed for deployment to heroku. 
This node.js app processes Qualcomm 2net device notifications and inserts device measurements 
into corresponding Force.com org.

See document "2Net Fitness app setup.pdf" for one time setup instructions of the Force.com app and information on how 
to obtain the Qualcomm 2net API key and secret pair required for both the 
Force.com app setup and this heroku node.js app setup.



To install the Force.com 2Net Fitness app:
1. Sign up for a free Salesforce.com Developer Environment at https://developer.salesforce.com/
2. Download and install the app from the Salesforce.com AppExchange listing here: https://appexchange.salesforce.com/listingDetail?listingId=a0N3000000B5WyfEAF

This heroku app is designed to support multiple Salesforce.com orgs running the 2Net Fitness app. Follow the instructions in
"2Net Fitness app setup.pdf" for each instance of the 2Net Fitness Force.com app that you setup.

### Deploying to Heroku

First generate a public key/private key pair for postgres encryption at rest. The demo app uses keys generated with RSA algorithm,
length 2048. Do not set a passphrase for the key pair.

In directory where you clone this repository:

Create heroku app:
>heroku create

Create postgres database on heroku:
>heroku addons:add heroku-postgresql:dev

Add pgcrypto extension to postgres database:
>heroku pg:psql --app your_heroku_app_name
>create extension pgcrypto;
>\q

Create schema in postgres database by running statements in file "create schema script.txt". 

Set environment variables on heroku. (For the JWTSecret variable, use a random sequence of 
approximately 20 letters and characters.)
>heroku config:set REDIRECT_URI=https://your_heroku_app_name.herokuapp.com/oauth/_callback
>heroku config:set DATABASE_URL=YOUR_POSTGRES_DATABASE_URL_ON_HEROKU
>heroku config:set QCKey=YOUR_QUALCOMM_KEY
>heroku config:set QCSecret=YOUR_QUALCOMM_SECRET
>heroku config:set QCEndpoint=https://twonetcom.qualcomm.com/kernel/
>heroku config:set JWTSecret=YOUR_JWT_TOKEN_SALT_STRING
>heroku config:set PUBKey='insert full pubkey string here'
>heroku config:set PRIVKey='insert full privkey string here'

Push the app to heroku:
>git push heroku master


### Optional worker process

This repository includes a sample worker process implemented in dbutils.js. dbutils.js could be modified to perform maintenance
tasks such as purging dated device notification records from the postgres database -- this is left as an exercise. dbutils.js
currently writes the number of notification records to the system log and is intended to be scheduled via the heroku scheduler
add on. Remove the following line from Procfile if you do not want to run this sample worker process:

worker: node dbutils.js
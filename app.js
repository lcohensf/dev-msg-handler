var express = require('express')
  , routes = require('./routes')
  , util = require('util')
  , async = require('async')
  , nforce = require('nforce')
  , pg = require('pg')
  , request = require('request')
  , fs = require('fs');


var oauth = []; // array of authentication objects, one per SF org, indexed by org id

var debugUI = process.env.DEBUG_UI || 'false';
function debugMsg(res, viewType, opts) {
	if (debugUI == 'true') {
		res.render(viewType, opts);
 	    res.end();
	}
	else {
		console.log(viewType + ':  ' + JSON.stringify(opts));
	}
}
var pgConnectionString = process.env.DATABASE_URL || 'postgres://postgres:misspiggy@localhost:5432/postgres';

var port = process.env.PORT || 3001; 
var redirRoute = '/oauth/_callback';
var redir = process.env.REDIRECT_URI || ('http://localhost:3001' + redirRoute);
//  org id, client secret and client key are different for each org; however, defaults may be in env
//  variables for one org used frequently for testing
var testingOrgId = process.env.CLIENT_ORG_ID || '';
var testingClientId = process.env.CLIENT_ID || '';
var testingClientSecret = process.env.CLIENT_SECRET || '';

var sslopts = {
   
      // pfx: fs.readFileSync('Qualcomm.crt') -- got an error trying this approach with salesforce generated cert
      
  // Specify the key file for the server
  key: fs.readFileSync('ssl/server.key'),
   
  // Specify the certificate file
  cert: fs.readFileSync('ssl/server.crt'),
   
  passphrase: '2netlab',
  
  // Specify the Certificate Authority certificate
  ca: fs.readFileSync('ssl/ca.crt'),
   
  // This is where the magic happens in Node.  All previous
  // steps simply setup SSL (except the CA).  By requesting
  // the client provide a certificate, we are essentially
  // authenticating the user.
  requestCert: false,
   
  // If specified as "true", no unauthenticated traffic
  // will make it to the route specified.
  rejectUnauthorized: false
};
// create the server
var app = module.exports = express.createServer(sslopts);

console.log("sslopts: " + JSON.stringify(sslopts);

// Configuration
app.configure(function(){
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});

app.configure('development', function(){
  app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function(){
  app.use(express.errorHandler());
});

// Routes
//app.get('/', routes.index);

app.get('/', function(req, res) {
	if (req.client.authorized) {
		res.render('index', { title: 'Salesforce - Qualcomm Device Message Handler' })
	} else {
		res.render('unauthorized', { title: 'Unauthorized for /' })
	}

});


app.get('/authOrg', function(req, res) {
	res.render("authOrg", 
		{ title: 'Enter Salesforce Authentication Information', 
		  defaults: {
		  	orgId: testingOrgId,
		  	clientId: testingClientId,
		  	clientSecret: testingClientSecret
		  }
		} );
});

function initSFOrgConnection(orgid, client_key, client_secret) {
	oauth[orgid] = {
		org_id: orgid, // also as field for convenience
		client_key: client_key,
		client_secret: client_secret
		// will build up additional fields as we create connection and authenticate
	};
	
	// use the nforce package to create a connection to salesforce.com

	oauth[orgid].connection = nforce.createConnection({
	  clientId: oauth[orgid].client_key,
	  clientSecret: oauth[orgid].client_secret,
	  clientOrgId: oauth[orgid].org_id,
	  redirectUri: redir,
	  mode: 'multi', // todo: support authentication to multiple orgs
	  apiVersion: 'v29.0',  // optional, defaults to v24.0
	  environment: 'production'  // optional, sandbox or production, production default
	});
	console.log('after createConnection');
	
	oauth[orgid].redirectURL  = oauth[orgid].connection.getAuthUri({state: oauth[orgid].org_id, display: 'popup', scope: ['full', 'refresh_token']});
	console.log('redirectURL = ' + oauth[orgid].redirectURL);
}

// will do lazy authentication as notification messages come from qualcomm or user authenticates via UI
app.post('/authenticate', function(req, res) {

	initSFOrgConnection(req.body.org_id, req.body.client_key, req.body.client_secret);
	
	res.redirect(oauth[req.body.org_id].redirectURL);
});

app.get(redirRoute, function(req, res) {
	console.log('in redirRoute, req.query: ' + JSON.stringify(req.query));
	if(!req.query.code) {
		console.log('Error receiving authorization from Salesforce');
		res.end();
	}
	var orgid = req.query.state;

	oauth[orgid].connection.authenticate({ code: req.query.code}, function(err, resp){
	  if(!err) {
		console.log('Access Token: ' + resp.access_token);
		oauth[orgid].oauthObj = resp;
		console.log('full oauth: ' + JSON.stringify(oauth[orgid].oauthObj));

		// store authentication info to postgres
		pg.connect(pgConnectionString, function(err, client, done) {
			if (err) {
				debugMsg(res, "error", {title: 'Unable to connect to postgres db.', data: err});
				return;
			}
			client.query('UPDATE "Qualcomm".oauth SET  active=false WHERE org_id=$1', [orgid], function(err) { // don't care about result param for update
				if (err) {
					debugMsg(res, "error", {title: 'Unable to clear any existing oauth records in postgres db for org: ' + orgid, data: err});
					return;
				}
				client.query('INSERT INTO "Qualcomm".oauth (org_id, client_id, client_secret, refresh_token, redirect_path, active) VALUES ($1, $2, $3, $4, $5, true)',
					[orgid, oauth[orgid].client_key, oauth[orgid].client_secret, oauth[orgid].oauthObj.refresh_token, oauth[orgid].redirectURL], 
					function(err, result) {
						done(); // release client back to the pool
						if (err) {
							debugMsg(res, "error", {title: 'Unable to insert to postgres db.', data: err});
							return;
						}
						res.render("authenticated", { title: 'Salesforce Authentication' } );
				});
			});	

		});
	  } else {
		debugMsg(res, "error", {title: 'Unable to authenticate.', data: err});
		return;
	  }
	});

	
});

//e.g. checkOrRefreshAuthentication(false, notification.sf_org_id, function(err, oauthElement) { ... });
function checkOrRefreshAuthentication(refresh, tOrgId, callback) {

	var self = this;
	if (refresh == 'false' && (typeof oauth[tOrgId] !== 'undefined') && (typeof oauth[tOrgId].oauthObj !== 'undefined')) {
		// appears we have authenticated this org; possible the access token is expired but we'll catch that on a DML execution
		console.log('refresh == false and found oauth object in memory on call to checkOrRefreshAuthentication');
		return callback(null, oauth[tOrgId]);
	}
	else {
	
		pg.connect(pgConnectionString, function(err, client, done) {
			if (err) {
				console.log('Attempting to check or refresh authentication. Unable to connect to postgres db. ' + JSON.stringify(err));
				return;
			}
			client.query('SELECT oauth.org_id, oauth.client_id, oauth.client_secret, oauth.refresh_token FROM "Qualcomm".oauth where org_id = $1 and oauth.active = true',	
				[tOrgId], 
				function(err, result) {
					done(); // release client back to the pool
					if (err) {
						return callback('Unable to retrieve registered device info from postgres db. - ' + err, null);
					}
					if (result.rows.length < 1) {
						return callback('unregistered org or previous authentication failed to store oauth record in postgres', null);
					}		

					console.log('retrieved oauth record: ' + JSON.stringify(result.rows[0]));
					oauth[tOrgId] = {};
					initSFOrgConnection(result.rows[0].org_id, result.rows[0].client_id, result.rows[0].client_secret);
					oauth[tOrgId].oauthObj = {refresh_token: result.rows[0].refresh_token};
					
					oauth[tOrgId].connection.refreshToken({oauth: oauth[tOrgId].oauthObj}, function(err, resp) {
						if (err) {
							return callback('Unable to refresh token for org: ' + tOrgId + '. ' + err, null);
			
						} else {
							oauth[tOrgId].oauthObj = resp;
							console.log('refresh token used data in db appears to have worked. full oauth: ' + JSON.stringify(oauth[tOrgId].oauthObj));
							return callback(null, oauth[tOrgId]);
						}
					});
			});
		});
	}

}

app.get('/simreg', function(req, res) {
	res.render("simreg", 
		{ title: 'Enter Device info', 
		  defaults: {
		  	sf_user_id: '',
		  	sf_org_id: '',
		  }
		} );
});

app.post('/register', function(req, res) {

	var dev = {
		sf_user_id: req.body.sf_user_id || '',		
		sf_org_id: req.body.sf_org_id || ''
	};

  pg.connect(pgConnectionString, function(err, client, done) {
		if (err) {
			
			console.log('Error connecting to postgres db: ' + JSON.stringify(err));	
			res.send(500, {status:500, message: 'Unable to connect to postgres db.', type:'internal'});
			return;
		}
		

			// just attempt insert; if record already exists ignore error
			client.query('INSERT INTO "Qualcomm".devices(sf_user_id, sf_org_id) ' +
				'VALUES ($1, $2)', 
				[dev.sf_user_id, dev.sf_org_id], 
				function(err, result) {
					done(); // release client back to the pool
					if (err) {	
						if (err.code == "23505")
						{
							// record already exists. that's ok
							console.log('Record already exists. No error. Device: ' + JSON.stringify(dev));	
						} else {
						
						console.log('Error inserting device: ' + JSON.stringify(err));	
						res.send(500, {status:500, message: 'Unable to insert device to postgres db.', type:'internal'});
						//debugMsg(res, "error", {title: 'Error inserting.', data: JSON.stringify(err)});
						return;
						}
					} else {
				
						console.log('Device inserted: ' + JSON.stringify(dev));													
					} 
			});	

	});		


  res.send(200, {status:200, message: 'Device registration successful', dev: JSON.stringify(dev)});
});



// insertMeasure may refresh oauthElement
// insertMeasure(category, ..., oauthElement, function(err, measureId, refreshedOauthElement) ...
function insertMeasure(category, sf_user_id, trackGuid, notificationId, aMeasureResponse, oauthElement, callback) {
	var aMeasure;						
	
	if (category == 'blood') {
		var aMR = aMeasureResponse.measureResponse.measures.measure;
		aMeasure = {
			Date_Time__c: aMR.time * 1000,
			glucose__c: aMR.blood.glucose,
			diastolic__c: aMR.blood.diastolic,
			map__c: aMR.blood.map,
			Pulse__c: aMR.blood.pulse,
			systolic__c: aMR.blood.systolic,
			spo2__c: aMR.blood.spo2,
			Device__r : { GUID__c: trackGuid }, 
			Health__r : { GUID__c: sf_user_id}, 
			Unique_Key__c: sf_user_id+':'+trackGuid+':'+aMR.time+':'+notificationId,
			Debug_Measurement__c: JSON.stringify(aMeasureResponse)				
		};
	}
	else if (category == 'activity') {	

		var aAR = aMeasureResponse.activityResponse.activities.activity;
		aMeasure = {
			Date_Time__c: aAR.endTime * 1000,
			Start_Time__c: aAR.startTime * 1000,
			Steps__c: aAR.steps,
			Mets__c: aAR.mets,
			Distance__c: aAR.distance,
			Calories__c: aAR.calories,
			Duration__c: aAR.duration,
			Device__r : { GUID__c: trackGuid }, 
			Health__r : { GUID__c: sf_user_id},
			type__c: aAR.type,
			Unique_Key__c: sf_user_id+':'+trackGuid+':'+aAR.startTime+':'+aAR.endTime+ ':'+notificationId,
			Debug_Measurement__c: JSON.stringify(aMeasureResponse)		
		};

	}
	else if (category == 'body') {
		var aMR = aMeasureResponse.measureResponse.measures.measure;
		aMeasure = {
			Date_Time__c: aMR.time * 1000,
        	weight__c: aMR.body.weight,
			Device__r : { GUID__c: trackGuid }, 
			Health__r : { GUID__c: sf_user_id},
        	Unique_Key__c: sf_user_id+':'+trackGuid+':'+aMR.time+':'+notificationId,
			Debug_Measurement__c: JSON.stringify(aMeasureResponse)
		};	
	}
	console.log('aMeasure to insert: ' + JSON.stringify(aMeasure));

	// currently only supporting insert of first measure or activity; nForce only supports insert of one object at a time
  var obj = nforce.createSObject('Measurement__c', aMeasure);
  oauthElement.connection.insert({sobject: obj, oauth: oauthElement.oauthObj}, function(err, resp){
  	// todo: is there any reason to implement idempotency?
	if (err) {
		// debug - next line
		//return callback('Error inserting measure. err: ' + JSON.stringify(err) + '. obj: ' + JSON.stringify(obj), null, oauthElement);

		// to do: check the err and only retry if it's an expired token
		
		console.log('Error inserting measure. Try to refresh token and retry once.');
		checkOrRefreshAuthentication(true, oauthElement.org_id, function(err, refreshedOauthElement) {
			if (err) {
				return callback('Error refreshing expired token: ' + err, null, null);
		
			} else {
				oauthElement = refreshedOauthElement;
				oauthElement.connection.insert({sobject: obj, oauth: oauthElement.oauthObj}, function(err, resp){
					if (err) {
						return callback('Error inserting measure after refreshing token. err: ' + JSON.stringify(err) + '. obj: ' + JSON.stringify(obj), null, oauthElement);
					} else {return callback(null, resp.id, oauthElement);} 
				});
			}
			
		});  

	} else {return callback(null, resp.id, oauthElement);} 	
  });

}

app.get('/Notification', function(req, res) {

	var qcEndpoint = 'https://twonetcom.qualcomm.com/kernel/';
	var qcKey = 'vh16CKn29ubka83Lad27';
	var qcSecret = 'WXx2tlAFkwDF2CPHekRfyXD78BeA3FAP';

	var notification = {
		id: '',
		sf_user_id: req.query.guid,
		trackGuid: req.query.trackGuid,
		trackName: req.query.trackName,
		category: req.query.category,
		startDate: req.query.startDate,
		endDate: req.query.endDate,
		sf_org_id: '',
		url: req.url
	};
	console.log('partially initialized notification record: ' + JSON.stringify(notification));

  //retrieve registered device record from postgres
  // todo - cache registered devices
  pg.connect(pgConnectionString, function(err, client, done) {
	if (err) {
		console.log('Handling /Notification, unable to connect to postgres db. ' + JSON.stringify(err));
		return;
	}
	client.query('SELECT devices.sf_org_id FROM "Qualcomm".devices WHERE devices.sf_user_id = $1',
		[notification.sf_user_id], 
		function(err, result) {
			if (err) {
				console.log('Handling /Notification, unable to retrieve registered device info from postgres db.' + JSON.stringify(err));
				return;
			}
			if (result.rows.length < 1) {
				console.log('Handling /Notification, the user for this device notification is not registered: ' + notification.sf_user_id);
				return;
			}
			notification.sf_org_id = result.rows[0].sf_org_id;
			console.log('result: ' + JSON.stringify(result.rows[0]));
			
							
		    // insert notification into postgres, retrieving id for record	
		    // to do: implement idempotency if needed... need to check if there's anything other than startDate and endDate
		    // that would clue me in as to a notification message being repeated
			var n = notification;
			client.query('INSERT INTO "Qualcomm".notifications(sf_user_id, "trackGuid", "trackName", category, "startDate", "endDate", sf_org_id, url) ' +
				'VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id', 
				[n.sf_user_id, n.trackGuid, n.trackName, n.category, n.startDate, n.endDate, n.sf_org_id, n.url], 
				function(err, result) {
					done(); // release client back to the pool
					if (err) {
						console.log('Handling /Notification, unable to insert notification to postgres db. ' + JSON.stringify(err));
						return;
					} else {
						notification.id = result.rows[0].id;	
						console.log('new notification id: ' + notification.id);	
																				
						// check that we are authenticated with this SF org, and if not authenticate with stored token
						checkOrRefreshAuthentication(false, notification.sf_org_id, function(err, oauthElement) {
							if (err) {
								console.log('Handling /Notification, no connection to SF org. Notification processing halted. '+ JSON.stringify(err));
								return;
							}				
		

							if (notification.category == 'blood' || notification.category == 'activity' || notification.category == 'body')
							{
								var catEndPoint = '';
								var catBodyTag = '';
								if (notification.category == 'blood') {
									catEndPoint = 'partner/measure/blood/filtered';
									catBodyTag = 'measureRequest';
								}
								else if (notification.category == 'activity') {
									catEndPoint = 'partner/activity/filtered';
									catBodyTag = 'activityRequest';
								}
								else if (notification.category == 'body') {
									catEndPoint = 'partner/measure/body/filtered';
									catBodyTag = 'measureRequest';
								}
				
								var options = {
									url: qcEndpoint + catEndPoint,
									method: 'POST',
									headers: {
										'Authorization': 'Basic '+ new Buffer(qcKey + ':' + qcSecret).toString('base64'),
										'Content-Type': 'application/xml',
										'Accept': 'application/json'
									},
									encoding: 'UTF-8', 
									body: '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'+
										'<' + catBodyTag + '>'+
										'<guid>'+notification.sf_user_id+'</guid>'+
										'<trackGuid>'+notification.trackGuid+'</trackGuid>'+
										'<filter>'+
										'<startDate>'+notification.startDate+'</startDate>'+
										'<endDate>'+notification.endDate+'</endDate>'+
										'</filter></' + catBodyTag + '>'

								}; // end options

								// define callback for Qualcomm's response
								function callback(error, response, body) {
									if (error || response.statusCode != 200) {
										console.log('Handling /Notification, error from Qualcomm on ' + notification.category + ' request. ' +JSON.stringify(error));
										return;
									}
									else {
										console.log('STATUS: ' + response.statusCode);
										console.log('HEADERS: ' + JSON.stringify(response.headers));

										var aMeasureResponse = JSON.parse(body);
										console.log('Response: ' + JSON.stringify(aMeasureResponse));

										insertMeasure(notification.category, notification.sf_user_id, notification.trackGuid, notification.id, aMeasureResponse, oauthElement, function(err, measureId, refreshedOauthElement) {
											if (err) {
											  console.log('Handling /Notification, error inserting new measure response: ' + JSON.stringify(err) + ' Measure response: ' + JSON.stringify(aMeasureResponse));
											  return;
											} else {
												res.redirect('/measurements__c/'+measureId+'?org='+notification.sf_org_id);
												res.end();
							  
											}
										});
									}
								};

								// retrieve measure from Qualcomm
								request(options, callback);
							} // end if (notification.category ...
						});	// checkOrRefreshAuthentication						
					} //  else 
			});	// client query insert	
		}); // client query select
	}); // pgConnect
	
	
});



// display the Measurement__c
app.get('/measurements__c/:id', function(req, res) {

  var async = require('async');
  var obj = nforce.createSObject('Measurement__c', {id: req.params.id});
  var corgid = req.query.org;

  async.parallel([
      function(callback){
        oauth[corgid].connection.query({query: "select count() from Measurement__c where id = '" + req.params.id + "'", oauth: oauth[corgid].oauthObj}, function(err, resp){
          callback(null, resp);
        });
      },
      function(callback){
        oauth[corgid].connection.getRecord({sobject: obj, oauth: oauth[corgid].oauthObj}, oauth[corgid].oauthObj, function(err, resp) {
          callback(null, resp);
        });
      },
  ],
  // optional callback
  function(err, results){
    res.render('showMeasurement', { title: 'Measurement Details', data: results });
  });  

});


app.listen(port, function(){
  console.log("Express server listening on port %d in %s mode", app.address().port, app.settings.env);
});

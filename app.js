/*
Copyright (c) 2011, salesforce.com, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the salesforce.com, Inc. nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
*/

var express = require('express')
  , routes = require('./routes')
  , util = require('util')
  , async = require('async')
  , nforce = require('nforce')
  , pg = require('pg')
  , request = require('request')
  , fs = require("fs")
  , jwt = require('jwt-simple');



var oauth = []; // array of authentication objects, one per SF org, indexed by org id
/*
	Fields in oauth objects array
	
	oauth[orgid] = {
		connection: '', //  returned by nforce.createConnection()
		redirectURL: '', // built up as part of creating connection to Salesforce
		oauthObj: '', // response from authentication flow, only care about refresh_token field	
		client_key: '', // SF org specific connected app key
		client_secret: '' // SF org specific connected app secret
	};
*/

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

var pgConnectionString = process.env.DATABASE_URL || '';
var port = process.env.PORT || 3001; 
var redirRoute = '/oauth/_callback';
var redir = process.env.REDIRECT_URI || ('http://localhost:3001' + redirRoute);
//  testingxxx variables used only for simplifying testing to prepopulate form field
var testingOrgId = process.env.CLIENT_ORG_ID || '';
var testingClientId = process.env.CLIENT_ID || '';
var testingClientSecret = process.env.CLIENT_SECRET || '';
// cannot package a connected app in an unmanaged package, so we cannot hold a single connected app ID and secret in env variables
//var connectedAppClientId = process.env.CLIENT_ID || '';
//var connectedAppClientSecret = process.env.CLIENT_SECRET || '';
var runlocal = redir.search('localhost') != -1;
var qcEndpoint = process.env.QCEndpoint || '';
var qcKey = process.env.QCKey || '';
var qcSecret = process.env.QCSecret || '';
var jwtSecret = process.env.JWTSecret || '';
var pubkey = '';
var privkey = '';
if (runlocal == true) {
	pubkey = fs.readFileSync('../public.key').toString();
	privkey = fs.readFileSync('../private.key').toString();
} else {
	pubkey = process.env.PUBKey || '';
	privkey = process.env.PRIVKey || '';
}

var pgcryptoinsert = 'INSERT INTO "Qualcomm".oauth("org_id", "refresh_token", "client_id", "client_secret") '
	+ 'SELECT vals.org_id, pgp_pub_encrypt(vals.refresh_token, keys.pubkey) as refresh_token, '
	+ 'pgp_pub_encrypt(vals.client_id, keys.pubkey) as client_id, pgp_pub_encrypt(vals.client_secret, keys.pubkey) as client_secret '
	+ 'FROM (VALUES ($1, $2, $3, $4)) as vals(org_id, refresh_token, client_id, client_secret) '
	+ 'CROSS JOIN (SELECT dearmor($5) as pubkey) as keys';
				
var noncryptoinsert = 	'INSERT INTO "Qualcomm".oauth (org_id, refresh_token, client_id, client_secret) VALUES ($1, $2, $3, $4)';

var pgcryptoselect = 'SELECT oauth.org_id, pgp_pub_decrypt(oauth.refresh_token, keys.privkey) as refresh_token_decrypt, '
		+ 'pgp_pub_decrypt(oauth.client_id, keys.privkey) as client_id_decrypt, pgp_pub_decrypt(oauth.client_secret, keys.privkey) as client_secret_decrypt '
		+ 'FROM "Qualcomm".oauth CROSS JOIN (SELECT dearmor($2) as privkey) as keys where oauth.org_id = $1';
		
var noncryptoselect = 	'SELECT oauth.org_id, oauth.refresh_token, client_id, client_secret FROM "Qualcomm".oauth where org_id = $1';
		
// create the server
var app = module.exports = express.createServer();



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

// global get controller
app.get('/*',function(req,res,next){
	res.header('X-Frame-Options', 'Deny');
    res.header('Cache-control' , 'no-store' );
    res.header('Pragma' , 'no-cache' );
    next();
});

// global post controller
app.post('/*',function(req,res,next){
	res.header('X-Frame-Options', 'Deny');
    res.header('Cache-control' , 'no-store' );
    res.header('Pragma' , 'no-cache' );
    next();
});

app.get('/', function(req, res){
	if(req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] === "http") {
    	console.log("Caught / over http. Redirecting to: " + "https://" + req.headers.host + req.url);
    	res.redirect("https://" + req.headers.host + req.url);
    	return;
	}

	//the rest of your logic to handle this route
	res.render('index', { title: 'Salesforce - Qualcomm Device Message Handler' });

});


app.get('/authOrg', function(req, res) {
	if(req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] === "http") {
    	console.log("Caught /authOrg over http. Redirecting to: " + "https://" + req.headers.host + req.url);
    	res.redirect("https://" + req.headers.host + req.url);
    	return;
	}

	var defaultOrgID = '';
	var defaultClientId = '';
	var defaultClientSecret = '';
	
	// check for debugUI flag and only show default values in UI if debug
	if (debugUI == 'true') {
		defaultOrgID = testingOrgId;
		defaultClientId = testingClientId;
		defaultClientSecret = testingClientSecret;
	} 
	
	res.render("authOrg", 
		{ title: 'Enter Salesforce Authentication Information', 
		  defaults: {
		  	orgId: defaultOrgID,
		  	clientId: defaultClientId,
		  	clientSecret: defaultClientSecret
		  }
		} );
});



function initSFOrgConnection(orgid) {
	
	// use the nforce package to create a connection to salesforce.com

	oauth[orgid].connection = nforce.createConnection({
	  clientId: oauth[orgid].client_key,
	  clientSecret: oauth[orgid].client_secret,
	  clientOrgId: orgid,
	  redirectUri: redir,
	  mode: 'multi', // todo: support authentication to multiple orgs
	  apiVersion: 'v29.0',  // optional, defaults to v24.0
	  environment: 'production'  // optional, sandbox or production, production default
	});
	console.log('after createConnection');
	
	oauth[orgid].redirectURL  = oauth[orgid].connection.getAuthUri({state: orgid, display: 'popup', scope: ['full', 'refresh_token']});
	console.log('redirectURL = ' + oauth[orgid].redirectURL);
}

// will do lazy authentication as notification messages come from qualcomm or user authenticates via UI
app.post('/authenticate', function(req, res) {
	
	if ((typeof req.body.org_id == 'undefined') || (typeof req.body.client_key == 'undefined') || (typeof req.body.client_secret == 'undefined')) {
		console.log('Handling /authenticate. Request body does not include required fields. Body: ' + JSON.stringify(req.body));
		res.send(400, {status:400, message: 'Incorrect format.'});
		res.end();
		 return;
	}
	
	oauth[req.body.org_id] = {
		client_key: req.body.client_key,
		client_secret: req.body.client_secret
	};
	initSFOrgConnection(req.body.org_id);
	
	res.redirect(oauth[req.body.org_id].redirectURL);
});

app.get('/authenticate', function(req, res) {
	res.send(404, {status:404, message: 'GET not supported.'});
	res.end();
});

app.get(redirRoute, function(req, res) {
	console.log('in redirRoute, req.query: ' + JSON.stringify(req.query));
	if(!req.query.code) {
		console.log('Error receiving authorization from Salesforce');
		res.send(500, {status:500, message: 'Internal error.'});
		res.end();
	}
	res.header('Content-Type', 'text/html; charset=utf-8'); // specifying charset to avoid potential Cross-site scripting vulnerability
	
	var orgid = req.query.state;

	oauth[orgid].connection.authenticate({ code: req.query.code}, function(err, resp){
	  if(!err) {
		//console.log('Access Token: ' + resp.access_token);
		oauth[orgid].oauthObj = resp;
		//console.log('full oauth: ' + JSON.stringify(oauth[orgid].oauthObj));
		
		// store authentication info to postgres
		pg.connect(pgConnectionString, function(err, client, done) {
			if (err) {
				console.log('Unable to connect to postgres db. err: ' + JSON.stringify(err));
				res.send(500, {status:500, message: 'Internal error.'});
				res.end();
				return;
			}
			// delete old record for org and then insert 
			client.query('DELETE FROM "Qualcomm".oauth WHERE org_id=$1', [orgid], function(err) { 
				if (err) {
					console.log('Unable to clear any existing oauth records in postgres db for org: ' + orgid + ' err: ' + JSON.stringify(err));
					res.send(500, {status:500, message: 'Internal error.'});
					res.end();
					return;
				}

				var insertstmt;
				var insertarray;
				
				if (runlocal == true) {
					insertstmt = noncryptoinsert;
					insertarray = [orgid, oauth[orgid].oauthObj.refresh_token, oauth[orgid].client_key, oauth[orgid].client_secret];
				} else {
					insertstmt = pgcryptoinsert;
					insertarray = [orgid, oauth[orgid].oauthObj.refresh_token, oauth[orgid].client_key, oauth[orgid].client_secret, pubkey];
				}
				
				//console.log('insertstmt: ' + insertstmt + '; insertarray: ' + JSON.stringify(insertarray));
				
				client.query(insertstmt, insertarray, 
					function(err, result) {
						done(); // release client back to the pool
						if (err) {
							console.log('Unable to insert to postgres db. err: ' + JSON.stringify(err));
							res.send(500, {status:500, message: 'Internal error.'});
							res.end();
							return;
						}
						//upsert jwtToken to SF org
						upsertJWTToken(jwt.encode({orgid: orgid}, jwtSecret), orgid, function(err) {
							if (err) {
							  console.log('Error inserting JWT token to SF org: ' + JSON.stringify(err));
							  res.send(500, {status:500, message: 'Internal error.'});
							  res.end();
							  return;
							} else {
								res.render("authenticated", 
									{ title: 'Salesforce Authentication'

									} );
							}
						});

				});
			});	

		});
		

		
	  } else {
		console.log('Unable to authenticate. err: ' + JSON.stringify(err));
		return;
	  }
	});

	
});

//e.g. checkOrRefreshAuthentication(false, notification.sf_org_id, function(err) { ... });
// pass false if you expect that there is a current authentication object in memory for the given org id; if there isn't this method
// will attempt to refresh the session token 
// pass true if you want to force a refresh of the session token without checking whether there is an authentication object in memory
function checkOrRefreshAuthentication(refresh, tOrgId, callback) {
	console.log('checkOrRefreshAuthentication, refresh = ' + refresh + ' orgId = ' + tOrgId);
	
	var self = this;
	if (refresh == false && (typeof oauth[tOrgId] !== 'undefined') && (typeof oauth[tOrgId].oauthObj !== 'undefined')) {
		// appears we have authenticated this org; possible the access token is expired but we'll catch that on a DML execution
		console.log('refresh == false and found oauth object in memory on call to checkOrRefreshAuthentication');
		return callback(null);
	}
	else {
	

		var selectstmt;
		var selectarray;

		if (runlocal == true) {
			selectstmt = noncryptoselect;
			selectarray = [tOrgId];
		} else {
			selectstmt = pgcryptoselect;
			selectarray = [tOrgId, privkey];
		}
		//console.log('selectstmt: ' + selectstmt + '; selectarray: ' + JSON.stringify(selectarray));
		
		pg.connect(pgConnectionString, function(err, client, done) {
			if (err) {
				console.log('Attempting to check or refresh authentication. Unable to connect to postgres db. ' + JSON.stringify(err));
				return;
			}
			client.query(selectstmt, selectarray, 
				function(err, result) {
					done(); // release client back to the pool
					if (err) {
						return callback('Unable to retrieve org authentication infromation from postgres db. - ' + JSON.stringify(err));
					}
					if (result.rows.length < 1) {
						return callback('unregistered org or previous authentication failed to store oauth record in postgres');
					}		

					//console.log('retrieved oauth record: ' + JSON.stringify(result.rows[0]));

					if (runlocal == true) {
						oauth[tOrgId] = {
							oauthObj: {refresh_token: result.rows[0].refresh_token},	
							client_key: result.rows[0].client_id,
							client_secret:  result.rows[0].client_secret
						};

					} else {
						oauth[tOrgId] = {
							oauthObj: {refresh_token: result.rows[0].refresh_token_decrypt},	
							client_key: result.rows[0].client_id_decrypt,
							client_secret: result.rows[0].client_secret_decrypt
						};
					}


					initSFOrgConnection(result.rows[0].org_id);

					
					
					oauth[tOrgId].connection.refreshToken({oauth: oauth[tOrgId].oauthObj}, function(err, resp) {
						if (err) {
							return callback('Unable to refresh token for org: ' + tOrgId + '. ' + err);
			
						} else {
							oauth[tOrgId].oauthObj = resp;
							//console.log('refresh token used data in db appears to have worked. full oauth: ' + JSON.stringify(oauth[tOrgId].oauthObj));
							return callback(null);
						}
					});
			});
		});
	}

}






app.post('/register', function(req, res) {
	if(req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] === "http") {
    	console.log("Caught /register over http. Redirecting to: " + "https://" + req.headers.host + req.url);
    	res.redirect("https://" + req.headers.host + req.url);
    	return;
	}
	
	if ((typeof req.body.sf_user_id == 'undefined') || (typeof req.body.sf_org_id == 'undefined') || (typeof req.body.jwt_token == 'undefined')) {
		console.log('Handling /register. Request body does not include required fields. Body: ' + JSON.stringify(req.body));
		res.send(400, {status:400, message: 'Incorrect format.'});
		res.end();
		 return;
	}
	
	var dev = {
		sf_user_id: req.body.sf_user_id || '',		
		sf_org_id: req.body.sf_org_id || '',
		jwt_token: req.body.jwt_token || ''
	};
	

	var decoded = jwt.decode(dev.jwt_token, jwtSecret);
	console.log('decoded = ' + decoded.orgid + '  sf_org_id = ' + dev.sf_org_id);
	if (decoded.orgid != dev.sf_org_id) {
		//res.render('unauthorized', { title: 'Unauthorized for registration of devices. Invalid JWT token.' });
		res.send(500, {status:500, message: 'Invalid request'});
		return;
	}


  pg.connect(pgConnectionString, function(err, client, done) {
		if (err) {
			
			console.log('Error connecting to postgres db: ' + JSON.stringify(err));	
			res.send(500, {status:500, message: 'Internal error.'});
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
						res.send(500, {status:500, message: 'Internal error.'});
						return;
						}
					} else {
				
						console.log('Device inserted: ' + JSON.stringify(dev));													
					} 
			});	

	});		


  res.send(200, {status:200, message: 'Success.'});
});

app.get('/register', function(req, res) {
	res.send(404, {status:404, message: 'GET not supported.'});
	res.end();
});

/*
app.get('/testrest', function(req,res) {
	var testOrgId = '00Do0000000HrIq'; 
	checkOrRefreshAuthentication(false, testOrgId, function(err) {
		if (err) {
			return callback('Error checking or refreshing authentication in testrest: ' + err);

		} else {

			oauth[testOrgId].connection.apexRest({oauth: oauth[testOrgId].oauthObj, uri: 'twonetfitness/SetKeys?jwt=12345'}, function(err, resp){
				if (err) {
					console.log('Error calling REST service: ' + JSON.stringify(err));
					res.send(500, {status:500, message: 'Internal error.'});
					res.end();
				} else {
					console.log('Response from calling SetKeys: ' + JSON.stringify(resp));
					res.send(200, {status:200, message: 'Ok'});
					res.end();
				} 
			});
		}
		
	}); 
});
*/

// upsertJWTToken(token, function(err) ...
function upsertJWTToken(tokenStr, orgid, callback) {

	console.log('*** in upsertJWTToken');
	checkOrRefreshAuthentication(false, orgid, function(err) {
		if (err) {
			return callback('Error checking or refreshing authentication in upsertJWTToken: ' + err);

		} else {
			var uriPath = 'twonetfitness/SetAPIKeys?JWTToken=' + tokenStr + '&OrgId=' + orgid + 
				'&TwoNetKey=' + qcKey + '&TwoNetSecret=' + qcSecret;
				
			//console.log('URIPath=' + uriPath);

			oauth[orgid].connection.apexRest({oauth: oauth[orgid].oauthObj, uri: uriPath}, function(err, resp){
				if (err) {
					console.log('Error calling REST service: ' + JSON.stringify(err));
					return callback('Error calling REST service: ' + err);
				} else {
					console.log('Response from calling SetAPIKeys: ' + JSON.stringify(resp));
					return callback(null);
				} 
			});
		}
		
	}); 	

}

/* original version when app was storing tokens and keys in encrypted fields on force.com 
// upsertJWTToken(token, function(err) ...
function upsertJWTToken(tokenStr, orgid, callback) {
	var tokenRecord = {
		token__c: tokenStr
	};						

	var obj = nforce.createSObject('JWTToken__c', tokenRecord);
	obj.setExternalId('orgid__c', orgid);
	console.log('object to upsert: ' + JSON.stringify(obj));
	checkOrRefreshAuthentication(false, orgid, function(err) {
		if (err) {
			return callback('Error checking or refreshing authentication: ' + err);

		} else {

			oauth[orgid].connection.upsert({sobject: obj, oauth: oauth[orgid].oauthObj}, function(err, resp){
				if (err) {
					console.log('Error inserting JWTToken. err: ' + JSON.stringify(err));
					return callback('Error inserting JWTToken: ' + err);
				} else {return callback(null);} 
			});
		}
		
	}); 

}
*/


function insertMeasures(category, orgid, sf_user_id, trackGuid, notificationId, aMeasureResponse) {

	var arraySize = 0;
	
	// ensure measures are in array; Qualcomm isn't consistent in JSON structure for filtered responses
	if (category == 'blood' || category == 'body') {	
		if (!(aMeasureResponse.measureResponse.measures.measure instanceof Array)) {
			aMeasureResponse.measureResponse.measures.measure = [aMeasureResponse.measureResponse.measures.measure];
		}
		arraySize = aMeasureResponse.measureResponse.measures.measure.length;
	} else if (category == 'activity') {
		if (!(aMeasureResponse.activityResponse.activities.activity instanceof Array)) {
			aMeasureResponse.activityResponse.activities.activity = [aMeasureResponse.activityResponse.activities.activity];		
		}
		arraySize = aMeasureResponse.activityResponse.activities.activity.length;
	} 
	var debugMeasurementText;
	if (arraySize == 1) {
		debugMeasurementText = JSON.stringify(aMeasureResponse);
	} else {
		debugMeasurementText =  'Measure response is for multiple measurements.';
	}
	
	var sfMeasures = []; // JSON format of measures to insert
	var objs = [];	// nForce objects to insert
	
	for (i = 0; i < arraySize; i++) {
			
		if (category == 'blood') {
			var aMR = aMeasureResponse.measureResponse.measures.measure[i];
			sfMeasures[i] = {
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
				Debug_Measurement__c: debugMeasurementText				
			};
		}
		else if (category == 'activity') {	
			var aAR = aMeasureResponse.activityResponse.activities.activity[i];
			sfMeasures[i] = {
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
				Debug_Measurement__c: debugMeasurementText		
			};

		}
		else if (category == 'body') {
			var aMR = aMeasureResponse.measureResponse.measures.measure[i];
			sfMeasures[i] = {
				Date_Time__c: aMR.time * 1000,
				weight__c: aMR.body.weight,
				Device__r : { GUID__c: trackGuid }, 
				Health__r : { GUID__c: sf_user_id},
				Unique_Key__c: sf_user_id+':'+trackGuid+':'+aMR.time+':'+notificationId,
				Debug_Measurement__c: debugMeasurementText
			};	
		}
		objs[i] = nforce.createSObject('twonetfitness__.Measurement__c', sfMeasures[i]);
	}
	
/*
//recursive pattern
var filenames = [...]

function uploader(i) {
  if( i < filenames.length ) {
    upload( filenames[i], function(err) {
      if( err ) {
        console.log('error: '+err)
      }
      else {
        uploader(i+1)
      }
    })
  }
}
uploader(0)
*/
	  
  
  	  //recursive pattern to insert multiple measures
  	  // only try to refresh token one time
  	  var refreshTokenTry = 0;
	  
	  function insertEachMeasure(i) {
	  	if (i < objs.length) {
	  	  console.log('about to insert measure: ' + JSON.stringify(sfMeasures[i]));
		  oauth[orgid].connection.insert({sobject: objs[i], oauth: oauth[orgid].oauthObj}, function(err, resp){

			if (err) {	
				console.log('Error inserting measure. ' + JSON.stringify(err));
				if (refreshTokenTry == 0) {
					console.log('Try refreshing token once per call to insertMeasures if error on insert.');
					refreshTokenTry = 1;
					checkOrRefreshAuthentication(true, orgid, function(err) {
						if (err) {
							console.log('Error refreshing expired token: ' + JSON.stringify(err));
							return;
						} else {
							oauth[orgid].connection.insert({sobject: objs[i], oauth: oauth[orgid].oauthObj}, function(err, resp){
								if (err) {
									console.log('Error inserting measure after refreshing token. err: ' + JSON.stringify(err) + '. obj: ' + JSON.stringify(objs[i]));
									return;
								} else {insertEachMeasure(i+1);} 
							});
						}
			
					});  
				}

			} else {
				insertEachMeasure(i+1);
			} 	
		  });
		}
  	  }
  	  insertEachMeasure(0); 


}

app.get('/Notification', function(req, res) {


	var insertMeasureFlag = true;

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
	/*
	if (notification.startDate != notification.endDate) {
		console.log('changing startDate to equal endDate, otherwise unknown how many measurements we may receive.');
		notification.startDate = notification.endDate;
		console.log('dates in notification record, updated: ' + JSON.stringify(notification));
	}
	*/

  //retrieve registered device record from postgres
  // todo - cache registered devices
  pg.connect(pgConnectionString, function(err, client, done) {
	if (err) {
		console.log('Handling /Notification, unable to connect to postgres db. ' + JSON.stringify(err));
		res.send(500, {status:500, message: 'Internal error.'});
		return;
	}
	client.query('SELECT devices.sf_org_id FROM "Qualcomm".devices WHERE devices.sf_user_id = $1',
		[notification.sf_user_id], 
		function(err, result) {
			if (err) {
				console.log('Handling /Notification, unable to retrieve registered device info from postgres db.' + JSON.stringify(err));
				res.send(500, {status:500, message: 'Internal error.'});
				return;
			}
			if (result.rows.length < 1) {
				console.log('Handling /Notification, the user for this device notification is not registered: ' + notification.sf_user_id);
				insertMeasureFlag = false;
				notification.sf_org_id =  'unknown user, org unknown';
			} else {
				notification.sf_org_id = result.rows[0].sf_org_id;
				//console.log('result: ' + JSON.stringify(result.rows[0]));
			}
			
			
							
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
						res.send(500, {status:500, message: 'Internal error.'});
						return;
					} else {
						notification.id = result.rows[0].id;	
						console.log('new notification id: ' + notification.id);	
						
						if (insertMeasureFlag == false) {
							res.send(200, {status:200, message: 'Success.'});
							return;
						} else {														
							// check that we are authenticated with this SF org, and if not authenticate with stored token
							checkOrRefreshAuthentication(false, notification.sf_org_id, function(err) {
								if (err) {
									console.log('Handling /Notification, no connection to SF org. Notification processing halted. '+ JSON.stringify(err));
									res.send(500, {status:500, message: 'Internal error.'});
									return;
								}				
		
								console.log ('Notification id: ' + notification.id + ' Category: ' + notification.category);
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
											res.send(500, {status:500, message: 'Internal error.'});
											return;
										}
										else {
											console.log('Received measurements back from Qualcomm, STATUS: ' + response.statusCode);
											//console.log('HEADERS: ' + JSON.stringify(response.headers));

											var aMeasureResponse = JSON.parse(body);
											//console.log('Response: ' + JSON.stringify(aMeasureResponse));

											// kick off inserts, running asynchronously and return ok
											insertMeasures(notification.category, notification.sf_org_id, notification.sf_user_id, notification.trackGuid, notification.id, aMeasureResponse);
											console.log('Inserts of measurements to SF org proceeding for notification id: ' + notification.id);
											res.send(200, {status:200, message: 'Success.'});
											return;

										}
									};

									// retrieve measure from Qualcomm
									request(options, callback);
								} else {
									if (debugUI == 'true') {
										debugMsg(res, "error", {title: 'Unknown category. Notification id: ' + notification.id + ' Category: ' + notification.category});
									} else {
										console.log ('Unknown category. Notification id: ' + notification.id + ' Category: ' + notification.category);
										res.send(500, {status:500, message: 'Incorrect format.'});
										return;
									}
								}
								 // end if (notification.category ...
							});	// checkOrRefreshAuthentication	
						} // if insertMeasureFlag
											
					} //  else 
			});	// client query insert	
		}); // client query select
	}); // pgConnect
	
	
});

app.get('/simreg', function(req, res) {

	if (runlocal == true) {

		res.render("simreg", 
			{ title: 'Enter Device info', 
			  defaults: {
				sf_user_id: '',
				sf_org_id: testingOrgId,
				jwt_token: jwt.encode({orgid: testingOrgId}, jwtSecret)
			  }
			} );
		
	} else {
		res.send(403, {status:403, message: 'Action not permitted.'});
		return;
	}

});


app.listen(port, function(){
  console.log("Express server listening on port %d in %s mode", app.address().port, app.settings.env);
});


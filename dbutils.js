var pg = require('pg');
var strftime = require('strftime')

var pgConnectionString = process.env.DATABASE_URL || '';

pg.connect(pgConnectionString, function(err, client, done) {
  client.query('SELECT count(*) AS c FROM "Qualcomm".notifications', function(err, result) {
    done();
    if(err) return console.error(err);
 
    console.log('Count of rows in notification table at time: ' + strftime('%B %d, %Y %H:%M:%S') + ' is: ' + result.rows[0].c);
    process.exit(0);
  });
});

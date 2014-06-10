
/*
 * GET home page.
 */

exports.index = function(req, res){
  res.render('index', { title: 'Salesforce - Qualcomm Device Message Handler' })
};


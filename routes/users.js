var request = require('request');
var express = require('express');
var router = express.Router();
var fs = require('fs'); 

/*
  ALL OF THE ROUTES IN THIS PAGE REQUIRE AN AUTHENTICATED USER
*/
console.log("Users %d",8);

/* GET users listing. */
router.get('/', function(req, res, next) {

  //console.log(JSON.parse(req) +" HAHHAH")
  
  fs.appendFile('userInfo.txt', JSON.stringify(req.user)+"\r\n", function (err) {
  if (err) throw err;
  console.log('Saved!');
}); 

  res.render('users', {
    title: 'Users',
    user: req.user
  });
});

/* GET the profile of the current authenticated user */
router.get('/profile', function(req, res, next) {
  request.get(
    `https://bia-dev.onelogin.com/oidc/2/me`,   
    {
    'auth': {
      'bearer': req.session.accessToken
    }
  },function(err, respose, body)
  {

    console.log('User FF')
	
    console.log(req);

    res.render('profile', {
      title: 'Profile',
      user: JSON.parse(req)
    });

  });
});

module.exports = router;

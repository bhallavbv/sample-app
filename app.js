const express = require('express');
const helmet = require('helmet');

var request = require('request');

var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');

var passport = require('passport');
var passportSaml = require('passport-saml');

var app = express();
var cookieSession = require('cookie-session');

var index=require('./routes/index');
var users=require('./routes/users');;
const CryptoJS = require("crypto-js");

const router = express.Router();

    const SAML = require("saml-encoder-decoder-js");
    const xmlParser = require("xml2json-light");
    const xml2js = require("xml2js");
    const util = require("util");
    
    const Saml2js = require("saml2js");
const { response } = require('express');

app.use(cookieParser());


passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

const strategy = new passportSaml.Strategy(
  {
      //https://login.salesforce.com?so=0sp2y0000008OJX
      //https://bia.my.salesforce.com/idp/login?app=0sp2y0000008OJX
	entryPoint: "https://bia.my.salesforce.com/idp/login?app=0sp2y0000008OJX",
    issuer: "passport-saml",
    cert: "MIIEpTCCA42gAwIBAgIOAXT8QaoNAAAAAGl0wNwwDQYJKoZIhvcNAQELBQAwgY4xJjAkBgNVBAMMHVNlbGZTaWduZWRDRVJUX2V4cDIwMjFPY3RvYmVyMRgwFgYDVQQLDA8wMEQxajAwMDAwMDJCUm0xFzAVBgNVBAoMDlNhbGVzZm9yY2UuY29tMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQswCQYDVQQIDAJDQTEMMAoGA1UEBhMDVVNBMB4XDTIwMTAwNjA0NTMxNVoXDTIxMTAwNjAwMDAwMFowgY4xJjAkBgNVBAMMHVNlbGZTaWduZWRDRVJUX2V4cDIwMjFPY3RvYmVyMRgwFgYDVQQLDA8wMEQxajAwMDAwMDJCUm0xFzAVBgNVBAoMDlNhbGVzZm9yY2UuY29tMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQswCQYDVQQIDAJDQTEMMAoGA1UEBhMDVVNBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6L4Qsfp1fGzxQkB0sYjDL8xAHq2nPUUohtW9RM9KZ6neI4ao0XmtNhDVXQ6g+J7za0Q7vSWUlpB2iG41FRHzNa4cEoEPzUYg1HfU2IKRHMUEdFXHaFD1yfa7rf7AUNq4QLSylBtM1IB1SMQXODH7qQMVoQcfETiPb+p4fr8uLAFCW/9r5ZOIQKBxFWayZQeIC1AJhNoQ2WgrmCPW91yIRZ0r84sq0Yg4ExdgwAEFaHiGNTgdYCU7jCLLRupIPLJP//4bHHqLsKtoF/j5KC8Mkk3FTbW7kdpNjjBGvdL6q7XgK91l7IKBw5Wjcw9B0TdjZGO2p+aPFaVcUSdwa27cZQIDAQABo4H+MIH7MB0GA1UdDgQWBBR1Q9uet8FQGKGhE3tWGEf4Pj15PzAPBgNVHRMBAf8EBTADAQH/MIHIBgNVHSMEgcAwgb2AFHVD2563wVAYoaETe1YYR/g+PXk/oYGUpIGRMIGOMSYwJAYDVQQDDB1TZWxmU2lnbmVkQ0VSVF9leHAyMDIxT2N0b2JlcjEYMBYGA1UECwwPMDBEMWowMDAwMDAyQlJtMRcwFQYDVQQKDA5TYWxlc2ZvcmNlLmNvbTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzELMAkGA1UECAwCQ0ExDDAKBgNVBAYTA1VTQYIOAXT8QaoNAAAAAGl0wNwwDQYJKoZIhvcNAQELBQADggEBANvsDKI+nYmensmv1JbC9uoHu1BE7G02berof1jnEbIlVJuSkp5m1Ev9f/itoRAQA4odyhgRbUbixSr7+QNNQSS0e5awtKM29z8MbAj/Nrxh9UVpsJ6Z95wvTx7p4nnFoBUc2SnwvSy2/irE1Xz/MY8fSNczejyn5nDkxA3sV/DzcW9KmXM1Ptli3QnSELZSp6gy7Q8cAaaFM7yXRd1bY9/6ft/4aynF3kWK+LEhmvc4cBzUsyrDlS+gDsZnjQ+wjiSQMY6eYjSPFw9jgjSOtIFJaviEVzgRw+rbCcmSET3al8pE6rA6LfxYFeLoF77o1HK2sO1fDflL/4kRaZRY7OU="
      
   },
  
 function (profile, done) 
 {
     console.log("Profile - "+profile.email);
      return done(null,
        {
          id: profile.uid,
          email: profile.email,
          displayName: profile.cn,
          firstName: profile.givenName,
          lastName: profile.sn
        });
 }
);

passport.use(strategy);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');


app.use(logger('dev'));
app.use(bodyParser.json());

app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'))); 

// Passport requires session to persist the authentication
// so were using express-session for this example


  app.use(session(
    {
      secret: 'secrettexthere',
      saveUninitialized: true,
      resave: true
    }));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Middleware for checking if a user has been authenticated
// via Passport and OneLogin OpenId Connect



function checkAuthentication(req,res,next)
{
 //   res.status(200).redirect(307, 'https://test-wallet.example.com/checkout/?param1=')
 
 

 
 //  res.render('https://boxinallsoftech.com/i',{parameterOne: xxx});
 

 
 

   // console.log("Response - "+util.inspect(res, {depth: null}));

    const xmlResponse = req.body.SAMLResponse;
	if(xmlResponse != null)
	{	
    const parser = new Saml2js(xmlResponse);
    req.samlUserObject = parser.toObject();
    var ciphertext = CryptoJS.AES.encrypt(req.samlUserObject['username'], 'siddhant').toString();
    console.log("OUTPUT - "+JSON.stringify(req.samlUserObject));
    
    console.log(ciphertext);
    res.status(200).redirect('http://localhost:4200/ssologin_data/?q='+ciphertext);
    //res.send(util.inspect(res, {depth: null}));
 
   // res.status(200).redirect(307,'http://localhost:4200/ssologin_data');
    
  if(req.samlUserObject.username != null || req.samlUserObject.username != '')
  {
	  console.log("Authenticated");
     
      next();
     

  } 
  else
  {	  
    res.redirect("/");
	  console.log("Not Authenticated");
  }
	}
	else
	{
       
		res.redirect("/");
	 // console.log("Not Authenticated");
	} 

}

app.use('/', index);
app.use('/users', checkAuthentication, users);


//res.status(200).redirect(307, 'https://test-wallet.example.com/checkout/?param1=')
    

const userAgentHandler = (req, res, next) => {
  const agent = useragent.parse(req.headers['user-agent']);
  const deviceInfo = Object.assign({}, {
    device: agent.device,
    os: agent.os,
  });
  req.device = deviceInfo;
  next();
};





/**
 * This Route Authenticates req with IDP
 * If Session is active it returns saml response
 * If Session is not active it redirects to IDP's login form
 */
 /**
router.get('/login/sso',
  passport.authenticate('saml', {
    successRedirect: '/',
    failureRedirect: '/login',
  }));


 * This is the callback URL
 * Once Identity Provider validated the Credentials it will be called with base64 SAML req body
 * Here we used Saml2js to extract user Information from SAML assertion attributes
 * If every thing validated we validates if user email present into user DB.
 * Then creates a session for the user set in cookies and do a redirect to Application
 */

  
  app.get('/login', passport.authenticate('saml', 
  {
  successReturnToOrRedirect: "/"
  }));

  app.post('/login/callback', passport.authenticate('saml', {
  callback: true,
  successReturnToOrRedirect: '/users',
  failureRedirect: '/'
}))



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

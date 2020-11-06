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
var users=require('./routes/users');



passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});
//"https://bia-dev.onelogin.com/trust/saml2/http-post/sso/a801d15c-f46a-447c-b256-106de17782cd",
//entryPoint: "https://bia-dev.onelogin.com/trust/saml2/http-post/sso/1a62b78f-9251-4b17-b732-a9baef373bd0",
//https://bia-dev.onelogin.com/trust/saml2/http-post/sso/d1cfb2df-830c-4629-8654-7e804ae481a5
// SAML strategy for passport -- Single IPD https://bia-dev.onelogin.com/trust/saml2/http-post/sso/
//https://bia-dev.onelogin.com/trust/saml2/http-post/sso/a801d15c-f46a-447c-b256-106de17782cd
//MIIDzzCCAregAwIBAgIUWTCE0/DisfVFFRsf3vez83ASnqkwDQYJKoZIhvcNAQEFBQAwQTEMMAoGA1UECgwDQklBMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAYBgNVBAMMEU9uZUxvZ2luIEFjY291bnQgMB4XDTIwMTEwMjIwMTcyNFoXDTI1MTEwMjIw MTcyNFowQTEMMAoGA1UECgwDQklBMRUwEwYDVQQLDAxPbmVMb2dpbiBJZFAxGjAY BgNVBAMMEU9uZUxvZ2luIEFjY291bnQgMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A MIIBCgKCAQEA0FxbNkednHlSUxmDE6hjEkIkV9dCqD1PuI/qFzjL8y6C7/NawEooGoc7kL+nsrJmhL0ct4snppKQH/IIrkf0Q8sUhs+4sZZtzMr0+mUydFbDKTDRVPeC9qVhob7T3HpSIUNSL3b83vGpZ5ZgLbYapKzgx85Zy2YwGjDNOoREna7iFfqcjoA8PC9gKyP5frrhitJ57ryOcNWZRuNbLF/lIysA+TU41XL6+1Fs2Zr+CF2oNr7EqRl6O7ZmGOQcVul0t2juipg0QIVgtuWKNSWtiAkTOIXm7PpLVBKWkLSr02lRuiKpNitsezJlYoE0pQwRdP3AC9JPDKGw7mw9YbcxJwIDAQABo4G+MIG7MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFNs41hw7eUXeU9v6GLdjgg0NkqxHMHwGA1UdIwR1MHOAFNs41hw7eUXeU9v6GLdjgg0NkqxHoUWkQzBBMQwwCgYDVQQKDANCSUExFTATBgNVBAsMDE9uZUxvZ2luIElkUDEaMBgGA1UEAwwRT25lTG9naW4gQWNjb3VudCCCFFkwhNPw4rH1RRUbH973s/NwEp6pMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQUFAAOCAQEAY1ph+5kAHnk24GrJaYGX9X2FMmjjD1jGKFQHG+JpqVp6O7L2RaZPM0Qg8Qla/mqCIwNINEingTE2IUxqOgwQMKCOfp09cW9TUw2kecjQAXg0sf7bPnlgajluIwYEvmby4rF3Se1eEpbZaGfeMETx5dC0UCZ2hkSoJ7ioMPFsl7+EFWND/3Juw1F1V04hR3ZmpzgTpcoT6rI770Lu4i5DQLAP4I/XBPNvJLDLHC9L5AFBVkONr1Z08zSNPLagIR33QTOCu/K7zo+pInp1v8KNEhwz+ucC9lg3tRHlZ0qLF6FH5QD3IbmjD2Q3Pcv2ZqUDU3okEqn+RkITnixddeYqnQ=="

const strategy = new passportSaml.Strategy(
  {
      //https://login.salesforce.com?so=00D2y000000uBiN
	entryPoint: "https://bia2.my.salesforce.com/idp/endpoint/HttpRedirect",
    issuer: "passport-saml",
    path:"http://upgrade-project.herokuapp.com/login/callback",
    cert: "MIIErDCCA5SgAwIBAgIOAXWcUJiBAAAAABDWMyswDQYJKoZIhvcNAQELBQAwgZAxKDAmBgNVBAMMH1NlbGZTaWduZWRDZXJ0XzA2Tm92MjAyMF8wNjQ4NDgxGDAWBgNVBAsMDzAwRDJ5MDAwMDAwdUJpTjEXMBUGA1UECgwOU2FsZXNmb3JjZS5jb20xFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xCzAJBgNVBAgMAkNBMQwwCgYDVQQGEwNVU0EwHhcNMjAxMTA2MDY0ODQ5WhcNMjExMTA2MDAwMDAwWjCBkDEoMCYGA1UEAwwfU2VsZlNpZ25lZENlcnRfMDZOb3YyMDIwXzA2NDg0ODEYMBYGA1UECwwPMDBEMnkwMDAwMDB1QmlOMRcwFQYDVQQKDA5TYWxlc2ZvcmNlLmNvbTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzELMAkGA1UECAwCQ0ExDDAKBgNVBAYTA1VTQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALgsw7ggO36KdPUk/5uv/c5R8QS5XJ3tKRRmk5leoOJSsV6VvSdXEVj3NuF3NLvG4dS9dOpGLJ2dDG+MtxOMeM8D8wTRctE8AAD8dDukRIFp1XAiSjwNqOx8dJMEuaFu2pZRjoyLKBd68zK/o5z3wRcywHJl9kzYBgI3orQbP/u5iKbedv+Ur6C5+eJffMF1z99wis92LXJp3a6jePd6KmMJOia/tz1NxDgif8Q1CFWsMVfl1RMVNUKZlRbSUAchZFAO4C7+GGwPv6fnYvBrx410ZaIRaPJhLZHf/FzEfRkpTIMEEPfVg0d3i4M0hEb8VYBZrxA7d/g4rv7hvjo5XIcCAwEAAaOCAQAwgf0wHQYDVR0OBBYEFH7Baefd6i+vfZaQNOqrnJQx9zvhMA8GA1UdEwEB/wQFMAMBAf8wgcoGA1UdIwSBwjCBv4AUfsFp593qL699lpA06quclDH3O+GhgZakgZMwgZAxKDAmBgNVBAMMH1NlbGZTaWduZWRDZXJ0XzA2Tm92MjAyMF8wNjQ4NDgxGDAWBgNVBAsMDzAwRDJ5MDAwMDAwdUJpTjEXMBUGA1UECgwOU2FsZXNmb3JjZS5jb20xFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xCzAJBgNVBAgMAkNBMQwwCgYDVQQGEwNVU0GCDgF1nFCYgQAAAAAQ1jMrMA0GCSqGSIb3DQEBCwUAA4IBAQBWeSPqojAFWVnQdTGyfGz3bcXjy65/veVom3BZHTFfCgfr4f8+ayBIMBVXjRqWbg8SPqa6CQFU59lXr2aG+UEcdC9CBQqOEI6m2qnlou9vvxx9MeQjPPBhEAt8hVaTH7GTIGv9A7Axku3MxKomkSbrvUb92sUoR+nlvgDEeYPI684eRPWwCeHMdLs8DqzXbD0eqxY3T+5Y2gLixLQLGRlLR2tedIFMipcydn9SShIVyZYiRRvqdZHIfPDN/IaMKTVgfVbSvT6Jx1uqCXY28YGCHe0Kt1BN+9KRLd/2arKmolyf4VcNG1cLTQXPDC0hXtmQGnPq0ncqHgBQiuXdzCG2"    },
  (profile, done) => done(null, profile),
);

passport.use(strategy);


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'hbs');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'))); 

// Passport requires session to persist the authentication
// so were using express-session for this example
app.use(cookieSession({
  name:'ss',
  secret: 'secret squirrel',
  cookie:{
	  maxAge: 1000*60*60*24*7 // 1 week
  },
   
  resave: true,    //false
  saveUninitialized: true,
  cookie:{secure:false}
}))

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Middleware for checking if a user has been authenticated
// via Passport and OneLogin OpenId Connect
function checkAuthentication(req,res,next)
{
	//console.log(req);
	//console.log(JSON.stringify(res));
    //console.log(JSON.stringify(next));
  if(req.isAuthenticated())
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

app.use('/', index);

app.use('/users', checkAuthentication, users);

// Initiates an authentication request with OneLogin
// The user will be redirect to OneLogin and once authenticated
// they will be returned to the callback handler below
/*app.get('/login', passport.authenticate('saml', {
  successReturnToOrRedirect: "/",
  scope: 'profile'
}));

// Callback handler that OneLogin will redirect back to
// after successfully authenticating the user
app.get('/oauth/callback', passport.authenticate('saml', {
  callback: true,
  successReturnToOrRedirect: '/users',
  failureRedirect: '/'
}))

// Destroy both the local session and
// revoke the access_token at OneLogin
app.get('/logout', function(req, res){

  request.post(`${baseUri}/token/revocation`, {
    'form':{
      'client_id': process.env.OIDC_CLIENT_ID,
      'client_secret': process.env.OIDC_CLIENT_SECRET,
      'token': req.session.accessToken,
      'token_type_hint': 'access_token'
    }
  },function(err, respose, body){

    console.log('Session Revoked at OneLogin');
    res.redirect('/');

  });
}); */

const userAgentHandler = (req, res, next) => {
  const agent = useragent.parse(req.headers['user-agent']);
  const deviceInfo = Object.assign({}, {
    device: agent.device,
    os: agent.os,
  });
  req.device = deviceInfo;
  next();
};


const router = express.Router();

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

  
  app.get('/login', passport.authenticate('saml', {
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

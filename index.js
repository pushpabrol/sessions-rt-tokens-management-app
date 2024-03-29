require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { auth, requiresAuth, claimCheck } = require('express-openid-connect');
const axios = require('axios');

//const requiresValidLogoutToken = require('./validateLogoutToken');

const { kv } = require("@vercel/kv");


async function getManagementApiToken() {
  const response = await axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
    grant_type: 'client_credentials',
    client_id: process.env.AUTH0_MANAGEMENT_CLIENT_ID,
    client_secret: process.env.AUTH0_MANAGEMENT_CLIENT_SECRET,
    audience: process.env.AUTH0_MANAGEMENT_API_AUDIENCE,
  });
  return response.data.access_token;
}

function customClaimCheck(claimCheck) {
    return function(req, res, next) {
      if (claimCheck(req, req.oidc.user)) {
        next(); 
        // Continue if claimCheck is true
      } else {
        // Redirect or render an error page
        res.render('error', { message: 'You are not authorized to view this!', isAuthenticated: req.oidc.isAuthenticated() });
      }
    };
  }

  async function checkSessionLogout(req, res, next) {
    const sid = req.oidc.user && req.oidc.user.sid; // Obtain session ID from request session. Adjust according to how your session ID is stored.
    if(sid && sid !== null){
    const isLoggedOut = await kv.get(`${sid}`);
    if (isLoggedOut) {
      req.logout(); 
      res.redirect('/login'); // Redirect to login page or handle as needed.
      return;
    }
    }
    next();
  }

  const onLogoutToken = async (token) => {
    console.log("In onLogoutToken");
    console.log(token);
    const { sid: logoutSid, sub: logoutSub } = token;
    // Note: you may not be able to access all sessions in your store
    // and this is likely to be an expensive operation if you have lots of sessions.
    await kv.set(logoutSid, Date.now(), { ex: 28800, nx: true });

  };
  

  


const app = express();
const port = 3000;
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // set to true if using https
}));

app.use(auth({
  authRequired: false,
  auth0Logout: true,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}/`,
  baseURL: process.env.BASE_URL || 'http://localhost:3000',
  clientID: process.env.AUTH0_CLIENT_ID,
  clientSecret:process.env.AUTH0_CLIENT_SECRET,
  secret: process.env.SESSION_SECRET,
  idpLogout: true,
  authorizationParams: {
    response_type: 'code',
    response_mode:"query",
    scope:"openid profile email sid"
  }
//   ,
//   backchannelLogout: {
//     onLogoutToken,
//     isLoggedOut: false,
//     onLogin: false,
//   }
}));
//app.use(checkSessionLogout);
app.set('view engine', 'ejs');
//app.set("views", "views");
const path = require('path');

app.set("views", path.join(__dirname, "views"));
//app.set('views', path.join(__dirname, '..', 'views'));

app.get('/', (req, res) => {
    if(req.oidc.isAuthenticated()) {
             console.log(req.oidc.idToken);
             console.log(req.oidc.idTokenClaims);

    }
  res.render('index', { isAuthenticated: req.oidc.isAuthenticated() });
});

app.post('/search-user', requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const email = req.body.email;
    const token = req.session.mgmtToken || await getManagementApiToken();
    const searchResponse = await axios.get(`https://${process.env.AUTH0_DOMAIN}/api/v2/users?q=email:"${email}"&search_engine=v3`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    console.log("Number of users found: " + searchResponse.data.length);
    if (searchResponse.data.length > 0) {
        res.render('users', { users: searchResponse.data, isAuthenticated: req.oidc.isAuthenticated() });

    } else {
        res.render('user-search', {isAuthenticated: req.oidc.isAuthenticated(), email : email, users : [] });
    }
  });
  

app.get('/users', requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const token = req.session.mgmtToken ||  await getManagementApiToken();
    req.session.mgmtToken = token;
    const response = await axios.get(`https://${process.env.AUTH0_DOMAIN}/api/v2/users`, {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    res.render('users', { users: response.data, isAuthenticated: req.oidc.isAuthenticated() });
  });


  app.get('/user-search',requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    res.render('user-search', {isAuthenticated: req.oidc.isAuthenticated()});
  });
  

  app.get('/user-sessions/:userId',requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {

    const token = req.session.mgmtToken ||  await getManagementApiToken();
    const userId = req.params.userId;
    const sessions = await axios.get(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${userId}/sessions`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    console.log(sessions.data);
    res.render('user-sessions', { sessions: sessions.data.sessions, isAuthenticated: req.oidc.isAuthenticated(), userId : userId  });
  });
  
  // Revoke all sessions for a user
  app.post('/revoke-sessions/:userId',requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const token = req.session.mgmtToken ||  await getManagementApiToken();
    const userId = req.params.userId;
    await axios.delete(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${userId}/sessions`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    res.redirect('/user-sessions/' + userId);
  });

  app.post('/revoke-session/:id', customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const token = req.session.mgmtToken ||  await getManagementApiToken();
    const id = req.params.id;
    const userId = req.body.userId;
    await axios.delete(`https://${process.env.AUTH0_DOMAIN}/api/v2/sessions/${id}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    res.redirect('/user-sessions/' + userId);
  });
  

  app.get('/user-refresh-tokens/:userId',requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const token = req.session.mgmtToken ||  await getManagementApiToken();
    const userId = req.params.userId;
    const tokens = await axios.get(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${userId}/refresh-tokens`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    console.log(tokens.data);
    res.render('user-rts', { tokens: tokens.data.tokens, user: userId, isAuthenticated: req.oidc.isAuthenticated(), userId : userId });
  });
  
  // Revoke all sessions for a user
  app.post('/revoke-refresh-tokens/:userId',requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const token = req.session.mgmtToken ||  await getManagementApiToken();
    const userId = req.params.userId;
    await axios.delete(`https://${process.env.AUTH0_DOMAIN}/api/v2/users/${userId}/refresh-tokens`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    res.redirect('/user-refresh-tokens/' + userId);
  });

  app.post('/revoke-refresh-token/:id',requiresAuth(),customClaimCheck((req, user) => {
    console.log("claims");
    return user.admin === true;
  }), async (req, res) => {
    const token = req.session.mgmtToken ||  await getManagementApiToken();
    const id = req.params.id;
    const userId = req.body.userId;
    await axios.delete(`https://${process.env.AUTH0_DOMAIN}/api/v2/refresh-tokens/${id}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    res.redirect('/user-refresh-tokens/' + userId);
  });


  app.get('/logout', (req, res) => {
    res.oidc.logout({ returnTo: process.env.BASE_URL || 'http://localhost:3000' });
  });


  app.post('/backchannel-logout', async (req, res) => {
    await kv.set(req.logoutToken.sid, Date.now(), { ex: 28800, nx: true });
    
  });




app.listen(port, () => console.log(`Listening on port ${port}`));

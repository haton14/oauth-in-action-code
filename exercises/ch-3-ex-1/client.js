const express = require("express");
const request = require("sync-request");
const url = require("url");
const qs = require("qs");
const querystring = require('querystring');
const cons = require('consolidate');
const randomstring = require("randomstring");
const __ = require('underscore');
__.string = require('underscore.string');

const app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
const authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information


/*
 * Add the client information in here
 */
const client = {
	client_id: "oauth-client-1",
	client_secret: "oauth-client-secret-1",
	redirect_uris: ["http://localhost:9000/callback"]
};

const protectedResource = 'http://localhost:9002/resource';

const state = randomstring.generate();

let access_token = null;
const scope = null;

app.get('/', (req, res) => {
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/authorize', (req, res)=> {
	const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: 'code',
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state
	});
	res.redirect(authorizeUrl);
});

app.get('/callback', (req, res)=> {
	if (req.query.state !== state) {
		res.render('error', {error: req.query.error});
		return;
	}
	const code = req.query.code;
	const form_data = qs.stringify({
		grant_type: 'authorization_code',
		code: code,
		redirect_uri: client.redirect_uris[0]
	});	
	const headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		Authorization: `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`
	};
	const tokRes = request('POST', authServer.tokenEndpoint, {
		body: form_data,
		headers: headers
	});
	const body = JSON.parse(tokRes.getBody());
	access_token = body.access_token;
	res.render('index', {access_token: access_token, scope: scope});
});

app.get('/fetch_resource', (req, res) => {
});

const buildUrl = (base, options, hash) => {
	const newUrl = url.parse(base, true);
	newUrl.search = undefined;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, (value, key, list) => {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

const encodeClientCredentials = (clientId, clientSecret) => Buffer.from(`${querystring.escape(clientId)}:${querystring.escape(clientSecret)}`).toString('base64');

app.use('/', express.static('files/client'));

const server = app.listen(9000, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;
  console.log('OAuth Client is listening at http://%s:%s', host, port);
});
 

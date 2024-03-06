const express = require("express");
const request = require("sync-request");
const url = require("url");
const qs = require("qs");
const querystring = require("querystring");
const cons = require("consolidate");
const randomstring = require("randomstring");
const __ = require("underscore");
__.string = require("underscore.string");

const app = express();

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/client");

// authorization server information
const authServer = {
	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
};

// client information

const client = {
	client_id: "oauth-client-1",
	client_secret: "oauth-client-secret-1",
	redirect_uris: ["http://localhost:9000/callback"],
	scope: "foo",
};

const protectedResource = "http://localhost:9002/resource";

let state = null;

let access_token = "987tghjkiu6trfghjuytrghj";
let scope = null;
let refresh_token = "j2r3oj32r23rmasd98uhjrk2o3i";

app.get("/", (req, res) => {
	res.render("index", {
		access_token: access_token,
		scope: scope,
		refresh_token: refresh_token,
	});
});

app.get("/authorize", (req, res) => {
	access_token = null;
	scope = null;
	state = randomstring.generate();

	const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
		response_type: "code",
		scope: client.scope,
		client_id: client.client_id,
		redirect_uri: client.redirect_uris[0],
		state: state,
	});

	console.log("redirect", authorizeUrl);
	res.redirect(authorizeUrl);
});

app.get("/callback", (req, res) => {
	if (req.query.error) {
		// it's an error response, act accordingly
		res.render("error", { error: req.query.error });
		return;
	}

	const resState = req.query.state;
	if (resState !== state) {
		console.log("State DOES NOT MATCH: expected %s got %s", state, resState);
		res.render("error", { error: "State value did not match" });
		return;
	}

	const code = req.query.code;

	const form_data = qs.stringify({
		grant_type: "authorization_code",
		code: code,
		redirect_uri: client.redirect_uris[0],
	});
	const headers = {
		"Content-Type": "application/x-www-form-urlencoded",
		Authorization:
			`Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`,
	};

	const tokRes = request("POST", authServer.tokenEndpoint, {
		body: form_data,
		headers: headers,
	});

	console.log("Requesting access token for code %s", code);

	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
		const body = JSON.parse(tokRes.getBody());

		access_token = body.access_token;
		console.log("Got access token: %s", access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			console.log("Got refresh token: %s", refresh_token);
		}

		scope = body.scope;
		console.log("Got scope: %s", scope);

		res.render("index", {
			access_token: access_token,
			scope: scope,
			refresh_token: refresh_token,
		});
	} else {
		res.render("error", {
			error:
				`Unable to fetch access token, server response: ${tokRes.statusCode}`,
		});
	}
});

app.get("/fetch_resource", (req, res) => {
	console.log("Making request with access token %s", access_token);

	const headers = {
		Authorization: `Bearer ${access_token}`,
		"Content-Type": "application/x-www-form-urlencoded",
	};

	const resource = request("POST", protectedResource, { headers: headers });

	if (resource.statusCode >= 200 && resource.statusCode < 300) {
		const body = JSON.parse(resource.getBody());
		res.render("data", { resource: body });
		return;
	}
		/*
		 * Instead of always returning an error like we do here, refresh the access token if we have a refresh token
		 */
		console.log(`resource status error code ${resource.statusCode}`);
		res.render("error", {
			error: `Unable to fetch resource. Status ${resource.statusCode}`,
		});
});

const refreshAccessToken = (req, res) => {
	/*
	 * Use the refresh token to get a new access token
	 */
};

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

const encodeClientCredentials = (clientId, clientSecret) => Buffer.from(
		`${querystring.escape(clientId)}:${querystring.escape(clientSecret)}`,
	).toString("base64");

app.use("/", express.static("files/client"));

const server = app.listen(9000, "localhost", () => {
	const host = server.address().address;
	const port = server.address().port;
	console.log("OAuth Client is listening at http://%s:%s", host, port);
});

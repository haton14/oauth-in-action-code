const express = require("express");
const url = require("url");
const bodyParser = require("body-parser");
const randomstring = require("randomstring");
const cons = require("consolidate");
const nosql = require("nosql").load("database.nosql");
const querystring = require("querystring");
const __ = require("underscore");
__.string = require("underscore.string");

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/authorizationServer");
app.set("json spaces", 4);

// authorization server information
const authServer = {
	authorizationEndpoint: "http://localhost:9001/authorize",
	tokenEndpoint: "http://localhost:9001/token",
};

// client information
const clients = [
	{
		client_id: "oauth-client-1",
		client_secret: "oauth-client-secret-1",
		redirect_uris: ["http://localhost:9000/callback"],
		scope: "foo bar",
	},
];

const codes = {};

const requests = {};

const getClient = (clientId) =>
	__.find(clients, (client) => client.client_id === clientId);

app.get("/", (req, res) => {
	res.render("index", { clients: clients, authServer: authServer });
});

app.get("/authorize", (req, res) => {
	const client = getClient(req.query.client_id);

	if (!client) {
		console.log("Unknown client %s", req.query.client_id);
		res.render("error", { error: "Unknown client" });
		return;
	}
	if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		console.log(
			"Mismatched redirect URI, expected %s got %s",
			client.redirect_uris,
			req.query.redirect_uri,
		);
		res.render("error", { error: "Invalid redirect URI" });
		return;
	}
	const rscope = req.query.scope ? req.query.scope.split(" ") : undefined;
	const cscope = client.scope ? client.scope.split(" ") : undefined;
	if (__.difference(rscope, cscope).length > 0) {
		// client asked for a scope it couldn't have
		const urlParsed = url.parse(req.query.redirect_uri);
		urlParsed.search = undefined; // this is a weird behavior of the URL library
		urlParsed.query = urlParsed.query || {};
		urlParsed.query.error = "invalid_scope";
		res.redirect(url.format(urlParsed));
		return;
	}

	const reqid = randomstring.generate(8);

	requests[reqid] = req.query;

	res.render("approve", { client: client, reqid: reqid, scope: rscope });
	return;
});

app.post("/approve", (req, res) => {
	const reqid = req.body.reqid;
	const query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		// there was no matching saved request, this is an error
		res.render("error", { error: "No matching authorization request" });
		return;
	}

	if (req.body.approve) {
		if (query.response_type === "code") {
			// user approved access
			const code = randomstring.generate(8);

			const user = req.body.user;

			const scope = __.filter(__.keys(req.body), (s) =>
				__.string.startsWith(s, "scope_"),
			).map((s) => s.slice("scope_".length));
			const client = getClient(query.client_id);
			const cscope = client.scope ? client.scope.split(" ") : undefined;
			if (__.difference(scope, cscope).length > 0) {
				// client asked for a scope it couldn't have
				const urlParsed = url.parse(query.redirect_uri);
				urlParsed.search = undefined; // this is a weird behavior of the URL library
				urlParsed.query = urlParsed.query || {};
				urlParsed.query.error = "invalid_scope";
				res.redirect(url.format(urlParsed));
				return;
			}

			// save the code and request for later
			codes[code] = {
				authorizationEndpointRequest: query,
				scope: scope,
				user: user,
			};

			const urlParsed = url.parse(query.redirect_uri);
			urlParsed.search = undefined; // this is a weird behavior of the URL library
			urlParsed.query = urlParsed.query || {};
			urlParsed.query.code = code;
			urlParsed.query.state = query.state;
			res.redirect(url.format(urlParsed));
			return;
		}
		// we got a response type we don't understand
		const urlParsed = url.parse(query.redirect_uri);
		urlParsed.search = undefined; // this is a weird behavior of the URL library
		urlParsed.query = urlParsed.query || {};
		urlParsed.query.error = "unsupported_response_type";
		res.redirect(url.format(urlParsed));
		return;
	}
	// user denied access
	const urlParsed = url.parse(query.redirect_uri);
	urlParsed.search = undefined; // this is a weird behavior of the URL library
	urlParsed.query = urlParsed.query || {};
	urlParsed.query.error = "access_denied";
	res.redirect(url.format(urlParsed));
	return;
});

app.post("/token", (req, res) => {
	const auth = req.headers.authorization;
	let clientId;
	let clientSecret;
	if (auth) {
		// check the auth header
		const clientCredentials = Buffer.from(auth.slice("basic ".length), "base64")
			.toString()
			.split(":");
		clientId = querystring.unescape(clientCredentials[0]);
		clientSecret = querystring.unescape(clientCredentials[1]);
	}

	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log("Client attempted to authenticate with multiple methods");
			res.status(401).json({ error: "invalid_client" });
			return;
		}

		clientId = req.body.client_id;
		clientSecret = req.body.client_secret;
	}

	const client = getClient(clientId);
	if (!client) {
		console.log("Unknown client %s", clientId);
		res.status(401).json({ error: "invalid_client" });
		return;
	}

	if (client.client_secret !== clientSecret) {
		console.log(
			"Mismatched client secret, expected %s got %s",
			client.client_secret,
			clientSecret,
		);
		res.status(401).json({ error: "invalid_client" });
		return;
	}

	if (req.body.grant_type === "authorization_code") {
		const code = codes[req.body.code];

		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.authorizationEndpointRequest.client_id === clientId) {
				const access_token = randomstring.generate();

				let cscope = null;
				if (code.scope) {
					cscope = code.scope.join(" ");
				}

				nosql.insert({
					access_token: access_token,
					client_id: clientId,
					scope: cscope,
				});

				console.log("Issuing access token %s", access_token);
				console.log("with scope %s", cscope);

				const token_response = {
					access_token: access_token,
					token_type: "Bearer",
					scope: cscope,
				};

				res.status(200).json(token_response);
				console.log("Issued tokens for code %s", req.body.code);

				return;
			}
			console.log(
				"Client mismatch, expected %s got %s",
				code.authorizationEndpointRequest.client_id,
				clientId,
			);
			res.status(400).json({ error: "invalid_grant" });
			return;
		}
		console.log("Unknown code, %s", req.body.code);
		res.status(400).json({ error: "invalid_grant" });
		return;
	}
	if (req.body.grant_type === "refresh_token") {
		nosql.find().make((builder) => {
			builder.where("refresh_token", req.body.refresh_token);
			builder.callback((err, tokens) => {
				if (tokens.length === 1) {
					const token = tokens[0];
					if (token.client_id !== clientId) {
						console.log(
							"Invalid client using a refresh token, expected %s got %s",
							token.client_id,
							clientId,
						);
						nosql.remove().make((builder) => {
							builder.where("refresh_token", req.body.refresh_token);
						});
						res.status(400).end();
						return;
					}
					console.log(
						"We found a matching refresh token: %s",
						req.body.refresh_token,
					);
					const access_token = randomstring.generate();
					const token_response = {
						access_token: access_token,
						token_type: "Bearer",
						refresh_token: req.body.refresh_token,
					};
					nosql.insert({ access_token: access_token, client_id: clientId });
					console.log(
						"Issuing access token %s for refresh token %s",
						access_token,
						req.body.refresh_token,
					);
					res.status(200).json(token_response);
					return;
				}
				console.log("No matching token was found.");
				res.status(401).end();
			});
		});
	} else {
		console.log("Unknown grant type %s", req.body.grant_type);
		res.status(400).json({ error: "unsupported_grant_type" });
	}
});

app.use("/", express.static("files/authorizationServer"));

// clear the database on startup
nosql.clear();
// inject our pre-baked refresh token
setTimeout(
	() =>
		nosql.insert({
			refresh_token: "j2r3oj32r23rmasd98uhjrk2o3i",
			client_id: "oauth-client-1",
			scope: "foo bar",
		}),
	5000,
);

const server = app.listen(9001, "localhost", () => {
	const host = server.address().address;
	const port = server.address().port;

	console.log(
		"OAuth Authorization Server is listening at http://%s:%s",
		host,
		port,
	);
});

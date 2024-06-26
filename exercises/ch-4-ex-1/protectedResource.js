const express = require("express");
const bodyParser = require("body-parser");
const cons = require("consolidate");
const nosql = require("nosql").load("database.nosql");
const __ = require("underscore");
const cors = require("cors");

const app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/protectedResource");
app.set("json spaces", 4);

app.use("/", express.static("files/protectedResource"));
app.use(cors());

const resource = {
	name: "Protected Resource",
	description: "This data has been protected by OAuth 2.0",
};

const getAccessToken = (req, res, next) => {
	/*
	 * Scan for an access token on the incoming request.
	 */
	let inToken = null;
	const auth = req.headers.authorization;
	if (auth && auth.toLowerCase().indexOf("bearer") === 0) {
		inToken = auth.slice("bearer ".length);
	} else if (req.body?.access_token) {
		// Form-encoded body
		inToken = req.body.access_token;
	} else if (req.query?.access_token) {
		inToken = req.query.access_token;
	}
	console.log("Incoming token: %s", inToken);
	nosql.one().make((builder) => {
		builder.where("access_token", inToken);
		builder.callback((err, token) => {
			if (token) {
				console.log("We found a matching token: %s", inToken);
			} else {
				console.log("No matching token was found.");
			}
			req.access_token = token;
			next();
			return;
		});
	});
};

app.options("/resource", cors());

/*
 * Add the getAccessToken function to this handler
 */
app.post("/resource", getAccessToken, cors(), (req, res) => {
	if (req.access_token) {
		res.json(resource);
	} else {
		res.status(401).end();
	}
});

const server = app.listen(9002, "localhost", () => {
	const host = server.address().address;
	const port = server.address().port;

	console.log("OAuth Resource Server is listening at http://%s:%s", host, port);
});

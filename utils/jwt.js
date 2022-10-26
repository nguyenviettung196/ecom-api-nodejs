const jwt = require("jsonwebtoken");
require("dotenv").config();

const createJWT = ({ payload }) => {
	const token = jwt.sign(payload, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_LIFETIME,
	});
	return token;
};

const isTokenValid = ({ token }) => jwt.verify(token, process.env.JWT_SECRET);

const attackCookiesToResponse = ({ res, user }) => {
	const token = createJWT({ payload: user });
	//send jwt via cookie
	const oneDay = 1000 * 60 * 60 * 24;
	res.cookie("token", token, {
		httpOnly: true,
		expires: new Date(Date.now() + oneDay),
		// only use https when enviroment is production
		secure: process.env.NODE_ENV === "production",
		signed: true,
	});
};

module.exports = { createJWT, isTokenValid, attackCookiesToResponse };

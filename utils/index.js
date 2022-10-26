const { createJWT, isTokenValid, attackCookiesToResponse } = require("./jwt");
const createTokenUser = require("./createTokenUser");
const checkPermissions = require("./checkPermission");

module.exports = {
	createJWT,
	isTokenValid,
	attackCookiesToResponse,
	createTokenUser,
	checkPermissions,
};

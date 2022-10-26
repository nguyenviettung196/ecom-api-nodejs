const express = require("express");
const { authenticateUser, authorizePermissions } = require("../middleware/authentication");
const {
	createReview,
	deleteReview,
	getAllReviews,
	getSingleReview,
	updateReview,
} = require("../controllers/reviewController");
const router = express.Router();

router
	.route("/")
	.get(getAllReviews)
	.post([authenticateUser], createReview);
router
	.route("/:id")
	.get(getSingleReview)
	.patch([authenticateUser], updateReview)
	.delete([authenticateUser], deleteReview);

module.exports = router;

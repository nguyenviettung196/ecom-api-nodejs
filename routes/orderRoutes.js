const express = require("express");
const { authenticateUser, authorizePermissions } = require("../middleware/authentication");
const router = express.Router();
const {
	createOrder,
	getAllOrders,
	getCurrentUserOrder,
	getSingleOrder,
	updateOrder,
} = require("../controllers/orderController");

router
	.route("/")
	.get(authenticateUser, authorizePermissions("admin"), getAllOrders)
  .post(authenticateUser, createOrder);
  
router.route("/showAllMyOrders").get(authenticateUser, getCurrentUserOrder);

router.route("/:id").get(authenticateUser, getSingleOrder).patch(authenticateUser, updateOrder);

module.exports = router;

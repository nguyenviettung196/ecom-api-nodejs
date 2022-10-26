const Review = require("../models/Review");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");
const Product = require("../models/Product");
const { checkPermissions } = require("../utils");

//  createReview, getAllReviews, getSingleReview, updateReview, deleteReview;

const createReview = async (req, res) => {
	const { product: productId } = req.body;
	const isValidProduct = await Product.findOne({ _id: productId });
	if (!isValidProduct) {
		throw new CustomError.NotFoundError(`No product with id: ${productId}`);
	}
	const alreadySubmited = await Review.findOne({ product: productId, user: req.user.userId });
	if (alreadySubmited) {
		throw new CustomError.BadRequestError("already submitted review for this product");
	}
	req.body.user = req.user.userId;
	const review = await Review.create(req.body);
	res.status(StatusCodes.CREATED).json({ review });
};

const getAllReviews = async (req, res) => {
	const reviews = await Review.find({}).populate({
		path: "product",
		select: "name company price",
	});
	res.status(StatusCodes.OK).json({ count: reviews.length, reviews });
};

const getSingleReview = async (req, res) => {
	const { id: reviewId } = req.params;
	const review = await Review.find({ _id: reviewId });
	if (!review) {
		throw new CustomError.NotFoundError(`No review with id: ${reviewId}`);
	}
	res.status(StatusCodes.OK).json({ review });
};

const updateReview = async (req, res) => {
	const { id: reviewId } = req.params;
	const { rating, title, comment } = req.body;
	if (!rating || !title || !comment) {
		throw new CustomError.BadRequestError("Please provide all values");
	}
	const review = await Review.findOne({ _id: reviewId });
	checkPermissions(req.user, review.user);
	review.rating = rating;
	review.title = title;
	review.comment = comment;
	await review.save();
	res.status(StatusCodes.OK).json({ review });
};

const deleteReview = async (req, res) => {
	const { id: reviewId } = req.params;
	const review = await Review.findOne({ _id: reviewId });
	if (!review) {
		throw new CustomError.NotFoundError(`No review with id: ${reviewId}`);
	}
	checkPermissions(req.user, review.user);
	await review.remove();
	res.status(StatusCodes.OK).json({ msg: "delete review success !" });
};

const getSingleProductReviews = async (req, res) => {
	const { id: productId } = req.params;
	const reviews = await Review.find({ product: productId });
	res.status(StatusCodes.OK).json({ count: reviews.length, reviews });
};

module.exports = {
	createReview,
	getAllReviews,
	getSingleReview,
	updateReview,
	deleteReview,
	getSingleProductReviews,
};

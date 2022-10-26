require("express-async-errors");
const express = require("express");
const dotenv = require("dotenv");
//database
const connectDB = require("./db/connect");
// routers
const authRouter = require("./routes/authRoutes");
const userRouter = require("./routes/userRoutes");
const productRouter = require("./routes/productRoutes");
const reviewRouter = require("./routes/reviewRoutes");
const orderRouter = require("./routes/orderRoutes");
//middleware
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const fileUpload = require("express-fileupload");
const cors = require("cors");
const rateLimiter = require("express-rate-limit");
const helmet = require("helmet");
const xss = require("xss-clean");
const mongoSanitize = require("express-mongo-sanitize");

const notFoundMiddleware = require("./middleware/not-found");
const errorHandlerMiddleware = require("./middleware/error-handler");
// handle async,apply to all controller automatically

dotenv.config({ path: "./.env" });

// now have all express functionality in app
const app = express();

app.set("trust proxy", 1);
app.use(
	rateLimiter({
		windowMs: 15 * 60 * 1000,
		max: 60,
		message: "Too many request from this IP,please try again in 15 minutes",
	})
);
app.use(helmet());
app.use(cors());
app.use(xss());
app.use(mongoSanitize());

if (process.env.NODE_ENV === "development") {
	app.use(morgan("dev"));
}

app.use(cors());
//Body parser,reading data from body in req.body
app.use(express.json());

app.use(express.static("./public"));
app.use(fileUpload());

//access cookies coming back from the browser
app.use(cookieParser(process.env.JWT_SECRET));

app.get("/", (req, res) => {
	res.send("hello world");
});
app.get("/api/v1", (req, res) => {
	// console.log(req.cookies);
	console.log(req.signedCookies);
	res.send("hello world");
});
//routes
app.use("/api/v1/auth", authRouter);
app.use("/api/v1/users", userRouter);
app.use("/api/v1/products", productRouter);
app.use("/api/v1/reviews", reviewRouter);
app.use("/api/v1/orders", orderRouter);

//error handle non-exist route
app.use(notFoundMiddleware);
//error handle exist route in app
app.use(errorHandlerMiddleware);

// url database
const DB = process.env.DATABASE.replace("<PASSWORD>", process.env.DATABASE_PASSWORD);

const port = process.env.PORT;
const start = async () => {
	try {
		await connectDB(DB);
		app.listen(port, () => {
			console.log(`App running on port ${port}`);
		});
	} catch (error) {
		console.log(error);
	}
};

start();


# E-commerce API (Nodejs)

###  1.Setup Express Server and connect DB
Create file `app.js`,create folder `/db`,create file `.env`.In `app.js`,Setup
express server.Import module `dotenv` to loads environment variables from `.env` file
```js
const express = require("express");
const dotenv = require("dotenv");

dotenv.config({ path: "./.env" });
// now have all express functionality in app
const app = express();
const port = process.env.PORT;
const start = async () => {
	try {
		app.listen(port, () => {
			console.log(`App running on port ${port}`);
		});
	} catch (error) {
		console.log(error);
	}
};
// start server
start();
```
In `.env` add some variables
```bash
NODE_ENV=development
DATABASE_USENAME=<access mongodb.com to create>
DATABASE_PASSWORD=<access mongodb.com to create>
DATABASE=mongodb+srv://tungnv:<PASSWORD>@ecom.n3vxvls.mongodb.net/?retryWrites=true&w=majority
PORT=5000
```
In folder `/db`,create `connect.js` and create `connectDB()` passing an argument `url`
```js
const mongoose = require("mongoose");

// take url from DATABASE in `.env`
const connectDB = (url) => {
	return mongoose.connect(url);
};

module.exports = connectDB;

```
In `app.js` ,to connect database,import `connectDB` from `/db`,take url from `.env` and 
passing it to `connectDB()`
```js
const connectDB = require("./db/connect");
...
// now have all express functionality in app
const app = express();

//database
// take url database in .env
const DB = process.env.DATABASE.replace("<PASSWORD>", process.env.DATABASE_PASSWORD);
...
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
```
### 2.Basic Routes
Import some middleware to hanlde error
```js
//middleware
const notFoundMiddleware = require("./middleware/not-found");
const errorHandlerMiddleware = require("./middleware/error-handler");
// handle async,apply to all controller automatically
require("express-async-errors");
...
const app = express();

//Body parser,reading data from body in req.body
app.use(express.json());

app.get("/", (req, res) => {
	res.send("hello world");
});

//error handle non-exist route
app.use(notFoundMiddleware);
//error handle exist route in app
app.use(errorHandlerMiddleware);
...
```
Add `morgan` package
```js
const morgan = require("morgan");
....
// now have all express functionality in app
const app = express();

if (process.env.NODE_ENV === "development") {
	app.use(morgan("dev"));
}
...
```
### 3. User module
Create `/models` folder,create `UserModel.js`,setup basic user model
```js
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  
});

const User = mongoose.model("User", userSchema);

module.exports = User;

```
Create schema with name,email,password (all type:String)
```js
const userSchema = new mongoose.Schema({
	name: {
		type: String,
		require: [true, "Please provide name"],
		minlength: 3,
		maxlength: 50,
	},
	email: {
		type: String,
		require: [true, "Please provide email"],
	},
	password: {
		type: String,
		require: [true, "Please provide password"],
		minlength: 6,
	},
	role: {
		type: String,
		enum: ["admin", "user"],
		default: "user",
	},
});

```
Import `validator` package to validate schema
```js
const validator = require('validator');
...
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    validate: [validator.isEmail, 'Please provide a valid email'],
	...
  },
...
```
### 4.Auth Routes Structure
Setup basic auth routes,create `/controllers` folder and `/routes` folder,in 
`/controllers` create `authController.js` and export (resgiter,login,logout)
function
```js
const register = async (req, res) => {
	res.send("register user");
};
const login = async (req, res) => {
	res.send("login user");
};
const logout = async (req, res) => {
	res.send("logout user");
};

module.exports = {
	register,
	login,
	logout,
};

```
In `/routes`,setup `authRoutes.js` file,import all controllers
```js
const express = require("express");
const router = express.Router();
const { login, logout, register } = require("../controllers/authController");

router.post("/register", register);
router.post("/login", login);
router.get("/logout", logout);

module.exports = router;

```
In `app.js`,import `authRoutes`
```js
...
//database
const connectDB = require("./db/connect");
// routers
const authRouter = require("./routes/authRoutes");
...
app.get("/", (req, res) => {
	res.send("hello world");
});
//routes
app.use("/api/v1/auth", authRouter);
...
```
### 5.Register user and Set User roles
In `authController.js` at `register()` function,import `User` model,check
email already exist with `.findOne()` query,if not create new user
```js
const User = require("../models/User");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");

const register = async (req, res) => {
	const { email } = req.body;
	const emailAlreadyExists = await User.findOne({ email });
	if (emailAlreadyExists) {
		throw new CustomError.BadRequestError("Email already exists");
	}
	const user = await User.create(req.body);
	res.status(StatusCodes.CREATED).json({ user });
};
```
In userSchema `User.js` add `unique:true` inside schema
```js
	email: {
		type: String,
		unique: true,
		require: [true, "Please provide email"],
		validate: [validator.isEmail, "Please provide a valid email"],
	},
```
In `authController.js` at `register()`,if the first user is creted,set this user to admin role
```js
const register = async (req, res, next) => {
	const { email, name, password } = req.body;
	...
	//first registered user is an admin
	const isFirstAccount = (await User.countDocuments({})) === 0;
	const role = isFirstAccount ? "admin" : "user";
	const user = await User.create({ email, name, password, role });
	res.status(StatusCodes.CREATED).json({ user });
};
```
### 6.Hash password
In `User.js` import `@bcryptjs`,create a `.pre('save')` hook to hash password before save
```js
// hash password
userSchema.pre("save", async function () {
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
});
```
Create an instance methods to check password hashed and password send from client
```js
//instance methods:  method available on all documents of a certain collection
userSchema.methods.correctPassword = async function (candidatePassword) {
	const isMatch = bcrypt.compare(candidatePassword, this.password);
	return isMatch;
};
```
### 7.JWT Setup
In `authController.js`, require `jsonwebtoken` package,create JWT
```js
const jwt = require("jsonwebtoken");
...
const register = async (req, res, next) => {
	...
	// sign token
	const tokenUser = { name: user.name, userId: user._id, role: user.role };
	const token = jwt.sign(tokenUser, "jwtSecret", { expiresIn: "1d" });
	res.status(StatusCodes.CREATED).json({ user: tokenUser, token });
};
```
Create `/utils` folder,add `index.js` and `jwt.js`,create jwt function and verify jwt function,
add variables in `.env` `JWT_SECRET` and `JWT_LIFETIME`
```js
//jwt.js
const jwt = require("jsonwebtoken");

const createJWT = ({ payload }) => {
	const token = jwt.sign(payload, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_LIFETIME,
	});
	return token;
};

const isTokenValid = ({ token }) => jwt.verify(token, process.env.JWT_SECRET);

module.exports = { createJWT, isTokenValid };
```
```js
const { createJWT, isTokenValid } = require("./jwt");

module.exports = { createJWT, isTokenValid };
```
```js
//authController.js
const { createJWT } = require("../utils");

const register = async (req, res, next) => {
	...
	// sign token
	const tokenUser = { name: user.name, userId: user._id, role: user.role };
	const token = createJWT(tokenUser);
	res.status(StatusCodes.CREATED).json({ user: tokenUser, token });
};
```
### 8.Cookie setup / send JWT via cookie
In `app.js`,import `@cookie-parser`, server access cookies coming from browser
```js
const cookieParser = require("cookie-parser");
...
//access cookies coming back from the browser
app.use(cookieParser());
...
```
In `/utils/jwt.js`,create `attackCookiesToResponse()`
```js
//jwt.js
const attackCookiesToResponse = ({ res, user }) => {
	const token = createJWT({ payload: user });

	//send jwt via cookie
	const oneDay = 1000 * 60 * 60 * 24;
		res.cookie("jwt", token, {
		httpOnly: true,
		expires: new Date(Date.now() + oneDay),
		// only use https when enviroment is production
		secure: process.env.NODE_ENV === "production",
	});
};
```
```js
// utils/index.js
const { createJWT, isTokenValid, attackCookiesToResponse } = require("./jwt");
module.exports = { createJWT, isTokenValid, attackCookiesToResponse };

```
```js
//authController.js
const { attackCookiesToResponse } = require("../utils");
...
const register = async (req, res, next) => {
	...
	// sign token
	const tokenUser = { name: user.name, userId: user._id, role: user.role };
	attackCookiesToResponse({ res, user: tokenUser });
	res.status(StatusCodes.CREATED).json({ user: tokenUser, token });
};
```
Add signature to cookie,set the secret to `cookieParser()`
```js
// app.js
app.use(cookieParser(process.env.JWT_SECRET));
```
```js
// utils/jwt.js
const attackCookiesToResponse = ({ res, user }) => {
	const token = createJWT({ payload: user });
	//send jwt via cookie
	const oneDay = 1000 * 60 * 60 * 24;
	res.cookie("jwt", token, {
		httpOnly: true,
		expires: new Date(Date.now() + oneDay),
		// only use https when enviroment is production
		secure: process.env.NODE_ENV === "production",
		signed: true,
	});
};
```
### 9.Login Route
- Check email and password exist,if one missing return 400\
- find user,if no user return 401
- check password,if does not match return 401
- if everything is correct,attack cookie and send back the same response as in register
In `authController.js`,at `login()`
```js
const login = async (req, res) => {
	const { email, password } = req.body;
	if (!email || !password) {
		throw new CustomError.BadRequestError("Please provide email and password");
	}
	const user = await User.findOne({ email });
	if (!user) {
		throw new CustomError.UnauthenticatedError("Invalid Credential");
	}
	const isPasswordCorrect = await user.correctPassword(password);
	if (!isPasswordCorrect) {
		throw new CustomError.UnauthenticatedError("Invalid Credential");
	}
	const tokenUser = { name: user.name, userId: user._id, role: user.role };
	attackCookiesToResponse({ res, user: tokenUser });
	res.status(StatusCodes.CREATED).json({ user: tokenUser });
};
```
### 10.Logout Route
- set token cookie equal to some string value
- set expires: new Date(Date.now())
```js
const logout = async (req, res) => {
	res.cookie("token", "random", {
		httpOnly: true,
		expires: new Date(Date.now()),
	});
	res.status(StatusCodes.OK).json({ msg: "user logged out!" });
};
```

### 11.User Routes
- add `userController.js` file
- export (getAllUsers,getSingleUser,showCurrentUser,updateUser,updateUserPassword) function
- res.send('some string value')
- setup useRoutes file
- import all controllers
- setup just one route - `router.route('/').get(getAllUsers);`
- import userRoutes as userRouter in the `app.js`
- setup `app.use('/api/v1/users',userRouter)`

In `userController.js`
```js
const getAllUsers =async (req, res) => {
	res.send("get all users");
};

const getSingleUser = async (req, res) => {
	res.send("get user");
};

const showCurrentUser = async (req, res) => {
	res.send("get current user");
};

const updateUser = async (req, res) => {
	res.send("update user");
};

const updateUserPassword = async (req, res) => {
	res.send("update user password");
};

module.exports = {
	getAllUsers,
	getSingleUser,
	showCurrentUser,
	updateUser,
	updateUserPassword,
};


```
In `userRoutes.js`
```js
const express = require("express");
const {
	getAllUsers,
	getSingleUser,
	showCurrentUser,
	updateUser,
	updateUserPassword,
} = require("../controllers/userController");
const { route } = require("./authRoutes");
const router = express.Router();

router.route("/").get(getAllUsers);
router.route("/showMe").get(showCurrentUser);
router.route("/updateUser").patch(updateUser);
router.route("/updateUserPassword").patch(updateUserPassword);
router.route("/:id").get(getSingleUser);

module.exports = router;
```
In `app.js`
```js
...
const userRouter = require("./routes/userRoutes");
...
app.use("/api/v1/users", userRouter);
```
#### GetAllUsers and GetSingleUser
- Get all users where role is 'user' and remove password
- Get single user where id matched id param and remove password
- If no user 404
In `userController.js`
```js
const User = require("../models/User");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");

const getAllUsers = async (req, res) => {
	const users = await User.find({ role: ["user", "admin"] }).select("-password");
	res.status(StatusCodes.OK).json({ result: users.length, users });
};

const getSingleUser = async (req, res) => {
	const user = await User.findOne({ _id: req.params.id }).select("-password");
	if (!user) throw new CustomError.NotFoundError(`No user with id: ${req.params.id}`);
	res.status(StatusCodes.OK).json({ user });
};
...
```
#### Authenticate User and Authorize Permissions
In `/middleware/authentication.js`,create 2 middleware function `authenticateUser`
 and `authorizePermissions`
 ```js
const CustomError = require("../errors");
const { isTokenValid } = require("../utils");

const authenticateUser = async (req, res, next) => {
	const token = req.signedCookies.token;
	if (!token) {
		throw new CustomError.UnauthenticatedError("Authentication invalid");
	}
	try {
		const { name, userId, role } = isTokenValid({ token });
		req.user = { name, userId, role };
		next();
	} catch (error) {
		throw new CustomError.UnauthenticatedError("Authentication invalid");
	}
};

const authorizePermissions =
	(...role) =>
	(req, res, next) => {
		if (!role.includes(req.user.role)) {
			throw new CustomError.UnauthorizedError("Unauthorized to access this route");
		}
	};
module.exports = { authenticateUser, authorizePermissions };
 ```
In `userRoutes.js`, add middleware to route
```js
const { authenticateUser, authorizePermissions } = require("../middleware/authentication");
 ...
router.route("/").get(authenticateUser, authorizePermissions("admin"), getAllUsers);
...
router.route("/:id").get(authenticateUser, getSingleUser);
```
#### Update User Password
- almost identical to login user
- add authenticateUser middleware in the route
- check for oldPassword and newPassword in the body
- if one missing 400
- look for user with req.user.userId
- check if oldPassword matches with user.comparePassword
- if no match 401
- if everything good set user.password equal to newPassword
- await user.save()
In `userController.js`
```js
const updateUserPassword = async (req, res) => {
	const { oldPassword, newPassword } = req.body;
	if (!oldPassword || !newPassword) {
		throw new CustomError.BadRequestError("Please provide both values");
	}
	const user = await User.findOne({ _id: req.user.userId });
	const isPasswordCorrect = await user.correctPassword(oldPassword);
	if (!isPasswordCorrect) {
		throw new CustomError.UnauthenticatedError("Invalid credentials");
	}
	user.password = newPassword;
	await user.save();
	res.status(StatusCodes.OK).json({ msg: "Success! password updated." });
};

```
#### Update User
- add authenticateUser middleware in the route
- check for name and email in the body
- if one is missing,send 400 (optional)
- use findOneAndUpdate()
- create token user, attackCookiesToResponse and send back the tokenUser
In `userRoutes.js`
```js
router.route("/updateUser").patch(authenticateUser, updateUser);
```
In `userController.js`
```js
const updateUser = async (req, res) => {
	const { email, name } = req.body;
	if (!email || !name) {
		throw new CustomError.BadRequestError("Please provide all values");
	}
	const user = await User.findOneAndUpdate(
		{ _id: req.user.userId },
		{ email, name },
		{ new: true, runValidators: true }
	);
	const tokenUser = createTokenUser(user);
	attackCookiesToResponse({ res, user: tokenUser });
	res.status(StatusCodes.OK).json({ user: tokenUser });
};
```
#### checkPermission function
(Only admin can see user info and itself,user just can see itself's info).

In `/utils` create `checkPermission.js` file
```js
const CustomError = require("../errors");
// If not 'admin' or not match 'userId',throw Error
const checkPermissions = (requestUser, resourceUserId) => {
	if (requestUser.role === "admin") return;
	if (requestUser.userId === resourceUserId.toString()) return;
	throw new CustomError.UnauthorizedError("Not authorized to access this route");
};

module.exports = checkPermissions;
```
In `userController.js` 
```js
const getSingleUser = async (req, res) => {
	const user = await User.findOne({ _id: req.params.id }).select("-password");
	if (!user) throw new CustomError.NotFoundError(`No user with id: ${req.params.id}`);
	checkPermissions(req.user, user._id);
	res.status(StatusCodes.OK).json({ user });
};
```


### 12.Product Model,Product Route,Product Controller
#### Product model
- create Product.js in models folder
- create Schema
- name : {type:String},price: {type:Number},description: {type:String},image: {type:String},category:{String},
- company:{type:String},colors:{type:String},featured:{type:Boolean},freeShipping:{type:Boolean},inventory:{type:Number}
- averageRating:{type:Number},user
- set timestamps
- exports Product model



```js
const mongoose = require("mongoose");

const ProductSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			trim: true,
			required: [true, "Please provide product name"],
			maxlength: [100, "Name can not be more than 100 characters"],
		},
		price: {
			type: String,
			default: 0,
			required: [true, "Please provide product price"],
		},
		description: {
			type: String,
			required: [true, "Please provide product description"],
			maxlength: [1000, "description can not be more than 1000 characters"],
		},
		image: {
			type: String,
			default: "/uploads/example.jpeg",
		},
		category: {
			type: String,
			required: [true, "Please provide product category"],
			enum: ["office", "kitchen", "bedroom"],
		},
		company: {
			type: String,
			required: [true, "Please provide product company"],
			enum: {
				values: ["ikea", "liddy", "macors"],
				message: "{VALUE} is not supported", // the value that user is providing
			},
		},
		colors: {
			type: [String],
			required: true,
		},
		features: { type: Boolean, default: false },
		freeShipping: { type: Boolean, default: false },
		inventory: { type: Number, required: true, default: 15 },
		averageRating: { type: Number, default: 0 },
		user: {
			type: mongoose.Types.ObjectId,
			ref: "User",
			required: true,
		},
	},
	{ timestamps: true }
);

module.exports = mongoose.model("Product", ProductSchema);

```

#### Product Routes

- add productController file in controller
- export (createProduct, getAllProducts, getSingleProduct, updateProduct, deleteProduct, uploadImage) functions
- res.send('function name')
- setup productRoutes file in routes
- import all controller
- only getAllProducts and getSingleProduct accessible in public
- rest only by admin (setup middlewares)
- typical setup
- router.route('/uploadImage').post(uploadImage)
- import productRoutes as productRouter in app.js
- setup app.use('/api/v1/products',productRouter)

In `productController.js`

```js
const createProduct = async (req, res) => {
	res.send("createProduct");
};

const getAllProducts = async (req, res) => {
	res.send("get all product");
};

const getSingleProduct = async (req, res) => {
	res.send("get product");
};

const updateProduct = async (req, res) => {
	res.send("update product");
};

const deleteProduct = async (req, res) => {
	res.send("delete product");
};

const uploadImage = async (req, res) => {
	res.send("upload image");
};

module.exports = {
	getAllProducts,
	createProduct,
	deleteProduct,
	getSingleProduct,
	updateProduct,
	uploadImage,
};

```


In `productRouter.js`

```js
const express = require("express");
const { authenticateUser, authorizePermissions } = require("../middleware/authentication");
const {
	createProduct,
	deleteProduct,
	getAllProducts,
	getSingleProduct,
	updateProduct,
	uploadImage,
} = require("../controllers/productController");
const router = express.Router();

router
	.route("/")
	.get(getAllProducts)
	.post([authenticateUser, authorizePermissions("admin")], createProduct);

router.route("/uploadImage").post([authenticateUser, authorizePermissions("admin")], uploadImage);

router
	.route("/:id")
	.get(getSingleProduct)
	.patch([authenticateUser, authorizePermissions("admin")], updateProduct)
	.delete([authenticateUser, authorizePermissions("admin")], deleteProduct);

module.exports = router;

```

In `app.js`

```js
...
const productRouter = require("./routes/productRoutes");
...
app.use("/api/v1/products", productRouter);
```

#### Create Product

- create user property on req.body and set it equal to userId (req.user)
- pass req.body into Product.create
- send back the product

In `productController.js`

```js
const Product = require("../models/Product");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");

const createProduct = async (req, res) => {
	req.body.user = req.user.userId;
	const product = await Product.create(req.body);
	res.status(StatusCodes.CREATED).json({ product });
};
...
```

#### Remaining productController
- getAllProducts,getSingleProduct,updateProduct,deleteProduct
- remember check already for role 'admin'

```js
const getAllProducts = async (req, res) => {
	const product = await Product.find({});
	res.status(StatusCodes.OK).json({
		result: product.length,
		product,
	});
};

const getSingleProduct = async (req, res) => {
	const { id: productId } = req.params;
	const product = await Product.findOne({ _id: productId });
	if (!product) {
		throw CustomError.NotFoundError(`No product with id : ${productId}`);
	}
	res.status(StatusCodes.OK).json({ product });
};

const updateProduct = async (req, res) => {
	const { id: productId } = req.params;
	const product = await Product.findByIdAndUpdate({ _id: productId }, req.body, {
		new: true,
		runValidators: true,
	});
	if (!product) {
		throw CustomError.NotFoundError(`No product with id : ${productId}`);
	}
	res.status(StatusCodes.OK).json({ product });
};

const deleteProduct = async (req, res) => {
	const { id: productId } = req.params;
	const product = await Product.findOne({ _id: productId });
	if (!product) {
		throw CustomError.NotFoundError(`No product with id : ${productId}`);
	}
	await product.remove();
	res.status(StatusCodes.OK).json({ msg: "success delete product" });
};

```
#### Import dev data

In `/mockData` create `import-dev-data.js` 

```js
const fs = require("fs");
require("dotenv").config();
const Product = require("../models/Product");
const connectDB = require("../db/connect");

const DB = process.env.DATABASE.replace("<PASSWORD>", process.env.DATABASE_PASSWORD);
connectDB(DB).then(() => {
	console.log("DB connection successful !");
});

const products = JSON.parse(fs.readFileSync(`${__dirname}/products.json`, "utf-8"));
// console.log(products);
const importData = async () => {
	try {
		await Product.create(products);
		console.log("Data successfully loaded!");
	} catch (error) {
		console.log(error);
	}
	process.exit();
};

//delete all data from collection
const deleteData = async () => {
	try {
		await Product.deleteMany();
		console.log("Data successfully deleted!");
	} catch (error) {
		console.log(error);
	}
	process.exit();
};
// console.log(process.argv);
if (process.argv[2] === "--import") {
	importData();
} else if (process.argv[2] === "--delete") {
	deleteData();
}

//bash : node mockData/import-dev-data.js --delete
//bash : node mockData/import-dev-data.js --import

```

#### Upload image controller

(See more about section: file/image-load)

Create `/public/uploads` folder

In `productController.js`

```js
...
const path = require("path");
...
const uploadImage = async (req, res) => {
	if (!req.files) {
		throw new CustomError.BadRequestError("No File Uploaded");
	}
	const productImage = req.files.image;
	if (!productImage.mimetype.startsWith("image")) {
		throw new CustomError.BadRequestError("Please upload image");
	}
	const maxSize = 1024 * 1024;
	if (productImage.size > maxSize) {
		throw new CustomError.BadRequestError("Please upload image smaller than 1MB");
	}
	const imagePath = path.join(__dirname, "../public/uploads/" + `${productImage.name}`);
	await productImage.mv(imagePath);
	res.status(StatusCodes.OK).json({ image: `/uploads/${productImage.name}` });
};
```
In `app.js`
```js
...
const fileUpload = require("express-fileupload");
...
app.use(express.static("./public"));
app.use(fileUpload());

```

### 13.Review Model,Controller,Routes

#### Review Model
- create Review.js in models folder
- create Schema
- rating: {type:NUmber},title:{type:String},comment:{type:String},user,product
- set timestamps
- export Review model

```js
const { default: mongoose } = require("mongoose");
const moongoose = require("mongoose");

const ReviewSchema = new moongoose.Schema(
	{
		rating: {
			type: Number,
			min: 1,
			max: 5,
			required: [true, "Please provide rating"],
		},
		title: {
			type: String,
			trim: true,
			required: [true, "Please provide review title"],
			maxlength: 100,
		},
		comment: {
			type: String,
			required: [true, "Please provide review text"],
		},
		user: {
			type: mongoose.Types.ObjectId,
			ref: "User",
			required: true,
		},
		product: {
			type: mongoose.Types.ObjectId,
			ref: "Product",
			required: true,
		},
	},
	{ timestamps: true }
);

ReviewSchema.index({ product: 1, user: 1 }, { unique: true });

module.exports = mongoose.model("Review", ReviewSchema);

```

#### Review Controller
- add reviewController file in controller
- export (createReview,getAllReviews,getSingleReview,updateReview,deleteReview) functions
- res.send('function name')
- setup reviewRoutes file in routes
- import all controllers
- only getAllReviews and getSingleReview accessible to public
- rest only to users (setup middlwares)
- typical REST setup
- import reviewRoutes as reviewRouter in the app.js
- setup app.use('/api/v1/reviews',productRouter)

Create `reviewController.js`

```js
const Review = require("../models/Review");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");

//  createReview, getAllReviews, getSingleReview, updateReview, deleteReview;

const createReview = async (req, res) => {
	res.send("create review");
};

const getAllReviews = async (req, res) => {
	res.send("get all review");
};

const getSingleReview = async (req, res) => {
	res.send("get single review");
};

const updateReview = async (req, res) => {
	res.send("update review");
};

const deleteReview = async (req, res) => {
	res.send("delete review");
};

module.exports = {
	createReview,
	getAllReviews,
	getSingleReview,
	updateReview,
	deleteReview,
};

```

Create `reviewRoutes.js`

```js
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

```

In `app.js`

```js
...
const reviewRouter = require("./routes/reviewRoutes");
...
	app.use("/api/v1/reviews", reviewRouter);
...
```
#### Create Review
- check for product in the req.body
- attack user property (set it equal to req.user.userId)
- create review

```js
const Review = require("../models/Review");
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");
const Product = require("../models/Product");
const { checkPermissions } = require("../utils");


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
```

#### getAllReviews and get getSingleReview
- both public routes, typical setup

```js
const getAllReviews = async (req, res) => {
	const reviews = await Review.find({});
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
```

#### deleteReview
- get id from req.params
- check if review exists
- if no review, 404
- check permissions (req.user,review.user)
- use await review.remove()
- send back 200

```js
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

```
#### Update review
- get id from req.params
- get {rating,title, comment} from req.body
- check if review exists
- if no review,404
- check permissions
- set review properties equal to rating, title, comment
- use await review.save()
- send back 200

```js
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
```

#### Populate method

Allow access reference documents in other collections

```js
const getAllReviews = async (req, res) => {
	const reviews = await Review.find({}).populate({
		path: "product",
		select: "name company price",
	});
	res.status(StatusCodes.OK).json({ count: reviews.length, reviews });
};
```

#### mongoose virtuals

Connect collections not connected,have to use `moongoose virtuals`.So essentially, create them on the fly when want to compute something

In `productController.js`,add populate method to connect with review collections

```js
const getSingleProduct = async (req, res) => {
	...
	const product = await Product.findOne({ _id: productId }).populate("reviews");
	...
};
```

In `Product.js`,add virtuals property 

```js
const ProductSchema = new mongoose.Schema(
	.....
	{ timestamps: true, toJSON: { virtuals: true }, toObject: { virtuals: true } }
);

ProductSchema.virtual("reviews", {
	ref: "Review", // Review model
	localField: "_id",
	foreignField: "product",
	justOne: false, // by default, a populated virtual is an array. If you set justOne:true, the populated virtual will be a single doc or null.
});
...
```

#### Single product reviews
In `reviewController.js`

```js
const getSingleProductReviews = async (req, res) => {
	const { id: productId } = req.params;
	const reviews = await Review.find({ product: productId });
	res.status(StatusCodes.OK).json({ reviews, count: reviews.length });
};
module.exports = {
	....
	getSingleProductReviews,
};
```

In `productRoutes.js`

```js
...
const { getSingleProductReviews } = require("../controllers/reviewController");
...
router.route("/:id/reviews").get(getSingleProductReviews);
```
#### Remove all reviews
Use pre `remove` hook to delete all review before delete product

In `Product.js`,create pre remove hook,use `this.model` to access review model,use `.deleteMany()`
and passing product id matches with the reviews

```js
ProductSchema.pre("remove", async function (next) {
	// this.model() can access different model not only actual model
	// {product} is property on review model that references the product
	await this.model("Review").deleteMany({ product: this._id });
});
```
#### Aggregate Pipeline

In `Review.js`,to calculate average rating,create `post save hook` , `post remove hook`, and 
`static method caculateAverageRating()`

```js
ReviewSchema.statics.calculateAverageRating = async function (productId) {
	// aggregate
	const result = await this.aggregate([
		{ $match: { product: productId } },
		{
			$group: {
				_id: null,
				avarageRating: { $avg: "$rating" },
				numOfReviews: { $sum: 1 },
			},
		},
	]);
	// console.log(result); //result is an obj array 
	//update info into collection
	try {
		await this.model("Product").findOneAndUpdate(
			{ _id: productId },
			{
				averageRating: Math.ceil(result[0]?.avarageRating || 0),
				numOfReviews: result[0]?.numOfReviews || 0,
			}
		);
	} catch (error) {
		console.log(error);
	}
};

ReviewSchema.post("save", async function () {
	// call static method need access actual schema go with `this.constructor`
	await this.constructor.calculateAverageRating(this.product);
});
ReviewSchema.post("remove", async function () {
	await this.constructor.calculateAverageRating(this.product);
});
```
## 14. Order

### Order Schema
- create Order.js in models folder
- create Schema
- tax: {type:Number},shippingFee:{type:Number},subtotal:{type:Number},total:{type:Number},
- orderItems:[],status:{type:String},user,clientSecret:{type:String},paymentId:{type:String},
- set timestamps
- export Order model

```js
const mongoose = require("mongoose");

const SingleCartItemSchema = mongoose.Schema({
	name: { type: String, required: true },
	image: { type: String, required: true },
	price: { type: Number, required: true },
	amount: { type: Number, required: true },
	product: {
		type: mongoose.Types.ObjectId,
		ref: "Product",
		required: true,
	},
});

const OrderSchema = new mongoose.Schema(
	{
		tax: { type: Number, required: true },
		shippingFee: { type: Number, required: true },
		subtotal: { type: Number, required: true },
		total: { type: Number, required: true },
		cartItems: [SingleCartItemSchema],
		status: {
			type: String,
			enum: ["pending", "failed", "paid", "delivered", "canceled"],
			default: "pending",
		},
		user: {
			type: mongoose.Types.ObjectId,
			ref: "User",
			required: true,
		},
		clientSecret: { type: String, required: true },
		paymentIntentId: { type: String },
	},
	{ timestamps: true }
);

module.exports = mongoose.model("Order", OrderSchema);

```

### Order Structure (controller)

- add orderController file in controllers
- export (getAllOrders,getSingleOrder,getCurrentUserOrder,createOrder,updateOrder) functions
- res.send('function name')
- setup orderRoutes file in routes
- import all controllers
- authenticate user in all routes
- getAllOrders admin only
- typical REST setup
- router.route('/showAllMyOrders').get(getCurrentUserOrders)
- import orderRoutes as orderRouter in the app.js
- setup app.use('/api/v1/orders',orderRouter)

In `orderController.js`

```js
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");

const createOrder = async (req, res) => {
  res.send("create order");
};

const getAllOrders = async (req, res) => {
	res.send("get all order");
};

const getSingleOrder = async (req, res) => {
	res.send("get single order");
};

const getCurrentUserOrder = async (req, res) => {
	res.send("get current order");
};

const updateOrder = async (req, res) => {
	res.send("update order");
};

module.exports = { getAllOrders, getSingleOrder, getCurrentUserOrder, createOrder, updateOrder };

```

In `orderRoutes.js`

```js
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
router.route("/:id").get(authenticateUser, getSingleOrder).patch(authenticateUser, updateOrder);
router.route("/showAllMyOrders").get(authenticateUser, getCurrentUserOrder);

module.exports = router;

```
In `app.js`
```js
...
const orderRouter = require("./routes/orderRoutes");
...
app.use("/api/v1/orders", orderRouter);
...
```

### Create Order

(See more about how create order work in stripe-payment section)

```js
const { StatusCodes } = require("http-status-codes");
const CustomError = require("../errors");
const { checkPermissions } = require("../utils");
const Order = require("../models/Order");
const Product = require("../models/Product");

const fakeStripeAPI = async ({ amount, currency }) => {
	const client_secret = "someValueHere";
	return { client_secret, amount };
};

const createOrder = async (req, res) => {
	const { items: cartItems, tax, shippingFee } = req.body;
	if (!cartItems || cartItems.length < 1) {
		throw new CustomError.BadRequestError("No cart items provided");
	}
	if (!tax || !shippingFee) {
		throw new CustomError.BadRequestError("Please provide tax and shipping fee");
	}
	let orderItems = [];
	let subtotal = 0;
	for (const item of cartItems) {
		const dbProduct = await Product.findOne({ _id: item.product });
		if (!dbProduct) {
			throw new CustomError.NotFoundError(`No product with id: ${item.product}`);
		}
		const { name, price, image, _id } = dbProduct;
		const singleOrderItem = {
			amount: item.amount,
			name,
			price,
			image,
			product: _id,
		};
		//add item to order
		orderItems = [...orderItems, singleOrderItem];
		//calculate subtotal
		subtotal += item.amount * price;
		console.log(orderItems);
		console.log(subtotal);
	}
	const total = tax + shippingFee + subtotal;
	//get client secret
	const paymentIntent = await fakeStripeAPI({
		amount: total,
		currency: "usd",
	});
	const order = await Order.create({
		orderItems,
		total,
		subtotal,
		tax,
		shippingFee,
		clientSecret: paymentIntent.client_secret,
		user: req.user.userId,
	});
	res.status(StatusCodes.CREATED).json({ order, clientSecret: order.clientSecret });
};

```
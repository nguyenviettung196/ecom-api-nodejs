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

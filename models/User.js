const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		require: [true, "Please provide name"],
		minlength: 3,
		maxlength: 50,
	},
	email: {
		type: String,
		unique: true,
		require: [true, "Please provide email"],
		validate: [validator.isEmail, "Please provide a valid email"],
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

// hash password
userSchema.pre("save", async function () {
	if (!this.isModified("password")) return;
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
});

//instance methods:  method available on all documents of a certain collection
userSchema.methods.correctPassword = async function (candidatePassword) {
	const isMatch = await bcrypt.compare(candidatePassword, this.password);
	return isMatch;
};

module.exports = mongoose.model("User", userSchema);

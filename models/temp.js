import { MongoClient } from "mongodb";
import { ObjectId } from "mongodb";

/*
 * Requires the MongoDB Node.js Driver
 * https://mongodb.github.io/node-mongodb-native
 */

const agg = [
	{
		$match: {
			product: new ObjectId("6358aa75ee32f8cd5c7db457"),
		},
	},
	{
		$group: {
			_id: null,
			averageRating: {
				$avg: "$rating",
			},
			numOfReviews: {
				$sum: 1,
			},
		},
	},
];

const client = await MongoClient.connect(
	"mongodb+srv://tungnv:mbEGZ4A4v0QPQClE@ecom.n3vxvls.mongodb.net/test",
	{ useNewUrlParser: true, useUnifiedTopology: true }
);
const coll = client.db("test").collection("reviews");
const cursor = coll.aggregate(agg);
const result = await cursor.toArray();
await client.close();

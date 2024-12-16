import mongoose from "mongoose"

import config from "@/app/api/v1/config"

declare global {
	// eslint-disable-next-line no-var
	var mongoose:
		| {
				conn: mongoose.Connection | null
				promise: Promise<mongoose.Connection> | null
		  }
		| undefined
}

interface CachedConnection {
	conn: mongoose.Connection | null
	promise: Promise<mongoose.Connection> | null
}

const MONGODB_URI = config.mongoUri

const cached: CachedConnection = global.mongoose ?? {
	conn: null,
	promise: null,
}

if (!global.mongoose) {
	global.mongoose = cached
}

async function dbConnect(): Promise<mongoose.Connection> {
	if (cached.conn) {
		return cached.conn
	}

	if (!cached.promise) {
		const opts = {
			bufferCommands: false,
		}

		cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongoose) => mongoose.connection)
	}

	try {
		cached.conn = await cached.promise
		return cached.conn
	} catch (e) {
		console.error(e)
		cached.promise = null
		cached.conn = null

		try {
			cached.promise = mongoose
				.connect(MONGODB_URI, { bufferCommands: false })
				.then((mongoose) => mongoose.connection)
			cached.conn = await cached.promise
			console.log("MongoDB connection re-established.")
			return cached.conn
		} catch (err) {
			console.error("Error reconnecting to MongoDB:", err)
			throw err
		}
	}
}

export default dbConnect

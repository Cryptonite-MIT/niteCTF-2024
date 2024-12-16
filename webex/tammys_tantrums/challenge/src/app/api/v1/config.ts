import dotenv from "dotenv"

dotenv.config()

const config = {
	mongoUri: process.env.MONGODB_URI || "mongodb://localhost:27017/tammys-tantrums",
	jwtSecret: process.env.JWT_SECRET || "fake-fake-fake-secret",
	maxTantrums: parseInt(process.env.MAX_TANTRUMS ?? "12"),
	minUsernameLen: parseInt(process.env.MIN_USERNAME_LEN ?? "5"),
}

export default config

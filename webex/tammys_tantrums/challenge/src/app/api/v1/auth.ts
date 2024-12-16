const bcrypt = require("bcryptjs")

export function comparePassword(plainTextPassword: string, hashedPassword: string): boolean {
	try {
		return bcrypt.compareSync(plainTextPassword, hashedPassword)
	} catch (error) {
		throw error
	}
}

export function hashPassword(plainTextPassword: string, saltRounds = 10): string {
	try {
		const salt = bcrypt.genSaltSync(saltRounds)
		const hash = bcrypt.hashSync(plainTextPassword, salt)
		return hash
	} catch (error) {
		throw error
	}
}

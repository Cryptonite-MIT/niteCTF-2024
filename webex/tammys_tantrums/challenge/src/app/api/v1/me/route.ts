import { cookies } from "next/headers"
import { NextResponse } from "next/server"

import config from "@/app/api/v1/config"
import { errorResponse, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import User from "@/lib/models/User"

const jwt = require("jsonwebtoken")

export async function GET(request: Request): Promise<NextResponse<unknown>> {
	try {
		const token = cookies().get("token")?.value
		const decoded = jwt.verify(token, config.jwtSecret) as { username: string }
		const { username } = decoded

		await dbConnect()

		const user = await User.findOne({ username })
		if (!user) {
			return NextResponse.redirect(new URL("/login", request.url))
		}

		return successResponse({ username: user.username })
	} catch (error) {
		if (error instanceof Error) {
			return errorResponse("Failed", error.message, 400)
		}
		return errorResponse("Failed", "An unexpected error occurred", 500)
	}
}

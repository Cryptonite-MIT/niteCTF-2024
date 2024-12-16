import { cookies } from "next/headers"
import { NextResponse } from "next/server"

import config from "@/app/api/v1/config"
import { errorResponse, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import { ITantrum } from "@/lib/models/Tantrum"
import User from "@/lib/models/User"

const jwt = require("jsonwebtoken")

export async function GET(
	request: Request,
	{ params }: { params: { username: string } }
): Promise<NextResponse<unknown>> {
	let username

	try {
		try {
			const cookie = request.headers.get("cookie")
			if (cookie) {
				const token = cookies().get("token")?.value

				const decoded = jwt.verify(token, config.jwtSecret) as { username: string }
				username = decoded.username
			}
		} catch {}

		await dbConnect()
		const user = await User.findOne({ username: params.username }).populate("tantrums")
		if (!user) {
			return errorResponse("Request failed", "User not found", 404)
		}

		const tantrums =
			username === params.username
				? user.tantrums || []
				: (user.tantrums || []).filter((tantrum: ITantrum) => !tantrum.isPrivate)
		return successResponse(tantrums)
	} catch (error) {
		console.error(error)
		return errorResponse("Request failed", "An unexpected error occurred", 500)
	}
}

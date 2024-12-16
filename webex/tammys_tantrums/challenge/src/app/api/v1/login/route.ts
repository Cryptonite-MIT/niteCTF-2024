import cookie, { serialize } from "cookie"
import { NextResponse } from "next/server"
import { z } from "zod"

import config from "@/app/api/v1/config"
import { ApiResponse, errorResponse, methodNotAllowed, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import User from "@/lib/models/User"

import { comparePassword } from "../auth"

const jwt = require("jsonwebtoken")

interface LoginProps {
	username: string
	password: string
}

const loginSchema = z.object({
	username: z.string().min(1, "Username is required"),
	password: z.string().min(1, "Password is required"),
})

export function GET(): NextResponse<ApiResponse<never>> {
	return methodNotAllowed(["POST"])
}

export async function POST(request: Request): Promise<NextResponse<unknown>> {
	try {
		if (!request.body) {
			return errorResponse("Authentication failed", "Request body is empty", 400)
		}

		const body = (await request.json()) as unknown as LoginProps
		const result = loginSchema.safeParse(body)

		if (!result.success) {
			return errorResponse("Authentication failed", result.error.errors[0].message, 400)
		}

		await dbConnect()

		const user = await User.findOne({ username: body.username })
		if (!user) {
			return errorResponse("Authentication failed", "Invalid credentials", 401)
		}

		if (!comparePassword(body.password, user.password)) {
			return errorResponse("Authentication failed", "Invalid credentials", 401)
		}

		const token = jwt.sign({ userId: user._id, username: user.username }, config.jwtSecret, {
			expiresIn: "24h",
		})

		const cookieOptions: cookie.SerializeOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 3600 * 24, // 1 day
			path: "/",
		}

		return successResponse(
			{ username: user.username },
			{
				headers: {
					"Set-Cookie": serialize("token", token, cookieOptions),
				},
			}
		)
	} catch (error) {
		if (error instanceof Error) {
			return errorResponse("Authentication failed", error.message, 500)
		}
		return errorResponse("Authentication failed", "An unexpected error occurred", 500)
	}
}

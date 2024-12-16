import { NextResponse } from "next/server"
import { z } from "zod"

import config from "@/app/api/v1/config"
import { ApiResponse, errorResponse, methodNotAllowed, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import User from "@/lib/models/User"

import { hashPassword } from "../auth"

interface RegisterProps {
	username: string
	password: string
	confirmPassword: string
	email: string
}

const registerSchema = z.object({
	username: z.string().min(config.minUsernameLen, `Username must be at least ${config.minUsernameLen} characters`),
	password: z.string().min(5, "Password must be at least 5 characters"),
})

export function GET(): NextResponse<ApiResponse<never>> {
	return methodNotAllowed(["POST"])
}

export async function POST(request: Request): Promise<NextResponse<unknown>> {
	try {
		if (!request.body) {
			return errorResponse("Registration failed", "Request body is empty", 400)
		}

		const body = (await request.json()) as unknown as RegisterProps
		const result = registerSchema.safeParse(body)

		if (!result.success) {
			return errorResponse("Registration failed", result.error.errors[0].message, 400)
		}

		await dbConnect()

		const existingUser = await User.findOne({ username: body.username })
		if (existingUser) {
			return errorResponse("Registration failed", "User with this username already exists", 409)
		}

		const hashedPassword = hashPassword(body.password)
		await User.create({
			username: body.username,
			password: hashedPassword,
		})

		return successResponse({})
	} catch (error) {
		if (error instanceof Error) {
			return errorResponse("An unexpected error occurred", error.message, 500)
		}
		return errorResponse("An unexpected error occurred", "", 500)
	}
}

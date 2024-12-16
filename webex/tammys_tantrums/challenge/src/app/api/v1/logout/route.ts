import { NextResponse } from "next/server"

import { errorResponse, successResponse } from "@/app/api/v1/utils"

export async function POST(): Promise<NextResponse<unknown>> {
	try {
		return successResponse(
			{ message: "Logout successful" },
			{
				headers: {
					"Set-Cookie": `token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
				},
			}
		)
	} catch {
		return errorResponse("An unexpected error occurred", "Internal Server Error", 500)
	}
}

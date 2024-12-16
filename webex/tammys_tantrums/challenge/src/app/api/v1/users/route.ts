import { cookies } from "next/headers"
import { NextResponse } from "next/server"

import config from "@/app/api/v1/config"
import { errorResponse, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import User from "@/lib/models/User"

const jwt = require("jsonwebtoken")

export async function GET(): Promise<NextResponse<unknown>> {
    try {
        const token = cookies().get("token")?.value
        jwt.verify(token, config.jwtSecret) as { userId: string }

        await dbConnect()
        const users = await User.aggregate([
            { $sample: { size: config.maxTantrums / 2 } },
            { $project: { username: 1, _id: 0 } },
        ])

        return successResponse(users.map((user) => user.username) || [])
    } catch (error) {
        if (error instanceof Error) {
            return errorResponse("Failed", error.message, 400)
        }
        return errorResponse("Request failed", "An unexpected error occurred", 500)
    }
}

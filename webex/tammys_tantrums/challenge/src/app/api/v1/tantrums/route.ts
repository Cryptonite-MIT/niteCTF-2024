import { cookies } from "next/headers"
import { NextResponse } from "next/server"
import { z } from "zod"

import config from "@/app/api/v1/config"
import { errorResponse, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import Tantrum from "@/lib/models/Tantrum"
import User from "@/lib/models/User"

const jwt = require("jsonwebtoken")

const tantrunCreateSchema = z.object({
    title: z.string().min(1, "Title is required").max(16, "Max character count exceeded"),
    description: z.string().max(162, "Max character count exceeded").optional(),
    isPrivate: z.boolean(),
    background: z.string().optional(),
    opacity: z.number().min(0).max(1).optional(),
})

export async function GET(): Promise<NextResponse<unknown>> {
    try {
        const token = cookies().get("token")?.value
        const decoded = jwt.verify(token, config.jwtSecret) as { userId: string }
        const { userId } = decoded

        await dbConnect()
        const user = await User.findById(userId).populate("tantrums")
        if (!user) {
            return errorResponse("Request failed", "User not found", 404)
        }

        return successResponse(user.tantrums || [])
    } catch (error) {
        console.error(error)
        return errorResponse("Request failed", "An unexpected error occurred", 500)
    }
}

export async function POST(request: Request): Promise<NextResponse<unknown>> {
    try {
        const cookie = request.headers.get("cookie")
        if (!cookie) {
            return errorResponse("Request failed", "No authentication token found", 401)
        }

        const { token } = cookie.split(";").reduce(
            (acc, cur) => {
                const [key, value] = cur.trim().split("=")
                acc[key] = value
                return acc
            },
            {} as { [key: string]: string }
        )

        const decoded = jwt.verify(token, config.jwtSecret) as { userId: string }
        const { userId } = decoded

        const body = await request.json()
        const result = tantrunCreateSchema.safeParse(body)
        if (!result.success) {
            return errorResponse("Request failed", result.error.errors[0].message, 400)
        }

        const { title, description, isPrivate, background, opacity } = result.data

        await dbConnect()
        const user = await User.findById(userId)
        if (!user) {
            return errorResponse("Request failed", "User not found", 404)
        }
        if (user.tantrums.length > config.maxTantrums) {
            return errorResponse("Request failed", "Tantrum quota exceeded", 403)
        }

        const newTantrum = new Tantrum({
            title,
            description,
            isPrivate,
            userId,
            background,
            opacity,
            date: new Date().toISOString(),
        })

        const savedTantrum = await newTantrum.save()
        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $push: { tantrums: savedTantrum._id } },
            { new: true }
        )

        if (!updatedUser) {
            await Tantrum.findByIdAndDelete(savedTantrum._id)
            return errorResponse("Request failed", "Tantrum not created", 500)
        }

        return successResponse(savedTantrum)
    } catch (error) {
        console.error(error)
        return errorResponse("Request failed", "An unexpected error occurred", 500)
    }
}

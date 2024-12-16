import { NextResponse } from "next/server"

import config from "@/app/api/v1/config"
import { errorResponse, successResponse } from "@/app/api/v1/utils"
import dbConnect from "@/lib/db"
import Tantrum from "@/lib/models/Tantrum"
import User from "@/lib/models/User"

const jwt = require("jsonwebtoken")

export async function DELETE(request: Request, { params }: { params: { id: string } }): Promise<NextResponse<unknown>> {
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
		const tantrumId = atob(params.id)

		await dbConnect()

		const whereStr = `function() { return this._id === '${tantrumId}' }`
		const tantrum = await Tantrum.findOne({
			$where: whereStr,
		})
		if (!tantrum) {
			return errorResponse("Request failed", "Tantrum not found", 404)
		} else if (tantrum.userId !== userId) {
			return errorResponse("Request failed", "Tantrum belongs to another user", 403)
		}

		const response = await Tantrum.findOneAndDelete({
			$where: whereStr,
		})
		if (!response) {
			return errorResponse("Request failed", "Failed to delete tantrum", 500)
		}

		const user = await User.findByIdAndUpdate(userId, { $pull: { tantrums: tantrumId } }, { new: true })
		if (!user) {
			return errorResponse("Request failed", "User not found", 404)
		}

		return successResponse({ message: "Tantrum deleted successfully" })
	} catch (error) {
		console.error(error)
		return errorResponse("Request failed", "An unexpected error occurred", 500)
	}
}

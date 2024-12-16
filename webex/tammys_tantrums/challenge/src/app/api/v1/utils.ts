import { NextResponse } from "next/server"

export interface ApiResponse<T> {
	ok: boolean
	message: string
	data?: T
	error?: string
}

export function methodNotAllowed(allowedMethods: string[]): NextResponse<ApiResponse<never>> {
	return NextResponse.json(
		{
			ok: false,
			message: "Method not allowed",
			error: `This endpoint only supports ${allowedMethods.join(", ")} methods`,
		} as ApiResponse<never>,
		{
			status: 405,
			headers: {
				Allow: allowedMethods.join(", "),
			},
		}
	)
}

export function successResponse<T>(
	data: T,
	options?: {
		headers?: Record<string, string>
		status?: number
	}
): NextResponse<ApiResponse<T>> {
	const response = NextResponse.json(
		{
			ok: true,
			data,
		} as ApiResponse<T>,
		{ status: options?.status || 200 }
	)

	if (options?.headers) {
		Object.entries(options.headers).forEach(([key, value]) => {
			response.headers.set(key, value)
		})
	}

	return response
}

export function errorResponse(message: string, error: string, status: number): NextResponse {
	return NextResponse.json(
		{
			ok: false,
			message,
			error,
		} as ApiResponse<never>,
		{ status }
	)
}

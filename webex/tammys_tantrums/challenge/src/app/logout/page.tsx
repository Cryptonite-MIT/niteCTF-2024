"use client"

import { useRouter } from "next/navigation"
import { useEffect } from "react"

export default function Logout(): JSX.Element {
	const router = useRouter()

	useEffect(() => {
		const logoutUser = async (): Promise<void> => {
			try {
				const response = await fetch("/api/v1/logout", {
					method: "POST",
					credentials: "include",
				})

				if (!response.ok) {
					console.error("Error logging out user:", response.status)
				}

				router.push("/login")
			} catch (error) {
				console.error("Error logging out user:", error)
				router.push("/login")
			}
		}

		logoutUser()
	}, [router])

	return (
		<div className="flex min-h-screen items-center justify-center bg-gray-100">
			<div className="rounded-lg bg-white p-8 shadow-md">
				<h2 className="mb-4 text-2xl font-bold">Logging out...</h2>
				<p className="text-gray-500">Please wait while we log you out.</p>
			</div>
		</div>
	)
}

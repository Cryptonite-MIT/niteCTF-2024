"use client"

import { useRouter } from "next/navigation"
import { FormEvent, useEffect, useState } from "react"

import About from "@/components/About"
import Footer from "@/components/Footer"
import Header from "@/components/Header"

export default function Register(): JSX.Element {
	const [username, setUsername] = useState("")
	const [password, setPassword] = useState("")
	const [error, setError] = useState("")
	const router = useRouter()

	useEffect(() => {
		async function checkAuth(): Promise<void> {
			try {
				await fetch("/api/v1/me", {
					method: "GET",
					credentials: "include",
				})
					.then((r) => r.json())
					.then((r) => {
						if (r.ok) {
							router.push("/login")
						}
					})
			} catch {}
		}

		checkAuth()
	}, [router])

	const handleSubmit = async (e: FormEvent<HTMLFormElement>): Promise<void> => {
		e.preventDefault()
		setError("")

		try {
			const response = await fetch("/api/v1/register", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify({ username, password }),
			})

			if (response.status >= 300 && response.status < 400) {
				const redirectUrl = response.headers.get("Location")
				if (redirectUrl) {
					router.push(redirectUrl)
					return
				}
			}

			const data = await response.json()
			if (!response.ok) {
				throw new Error(data.error || "Registration failed")
			}

			router.push("/login")
		} catch (err) {
			setError(err instanceof Error ? err.message : "An error occurred")
		}
	}

	return (
		<div className="flex min-h-screen flex-col bg-gray-100">
			<Header />
			<div className="relative mx-auto my-24 flex h-[60vh] w-full max-w-6xl items-center justify-center">
				<div className="relative w-[30rem] rounded-[2rem] bg-white p-12 shadow-xl">
					<div className="absolute left-0 right-0 top-0 h-24 rounded-t-[2rem] bg-gradient-to-b from-white/90 to-white/20" />
					<form className="relative space-y-6" onSubmit={handleSubmit}>
						<h2 className="mb-8 text-center text-3xl font-bold">Entre, ô homme troublé</h2>
						{error && (
							<div className="rounded-md bg-red-50 p-4 text-center text-sm text-red-500">{error}</div>
						)}
						<div className="space-y-2">
							<label className="block font-mono text-sm" htmlFor="username">
								Username
							</label>
							<input
								type="text"
								id="username"
								value={username}
								onChange={(e): void => setUsername(e.target.value)}
								className="w-full rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 font-mono focus:border-red-500 focus:outline-none"
								placeholder="tammy"
								required
								minLength={5}
							/>
						</div>
						<div className="space-y-2">
							<label className="block font-mono text-sm" htmlFor="password">
								Password
							</label>
							<input
								type="password"
								id="password"
								value={password}
								onChange={(e): void => setPassword(e.target.value)}
								className="w-full rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 font-mono focus:border-red-500 focus:outline-none"
								placeholder="t@MMy"
								required
								minLength={5}
							/>
						</div>
						<button
							type="submit"
							className="w-full rounded-lg bg-gradient-to-r from-red-500 to-red-600 px-4 py-3 font-bold text-white transition-colors hover:from-red-600 hover:to-red-700">
							Register
						</button>
						<p className="text-center text-sm text-gray-600">
							Already have an account?{" "}
							<a href="/login" className="text-red-500 hover:text-red-600">
								Login
							</a>
						</p>
					</form>
				</div>
			</div>
			<About />
			<Footer />
		</div>
	)
}

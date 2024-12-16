"use client"

import { useRouter } from "next/navigation"
import { FormEvent, useEffect, useState } from "react"

import { Tantrum } from "@/app/utils"
import About from "@/components/About"
import Footer from "@/components/Footer"
import Header from "@/components/Header"

import { generateGradient } from "../utils"

export default function EditTantrums(): JSX.Element {
	const isPrivate = true
	const [tantrums, setTantrums] = useState<Tantrum[]>([])
	const [newTantrum, setNewTantrum] = useState<Partial<Tantrum>>({
		isPrivate,
		background: generateGradient(),
		opacity: 0.9,
	})
	const [loggedIn, setLoggedIn] = useState<boolean>(false)
	const [username, setUsername] = useState<string>("")
	const [error, setError] = useState("")
	const router = useRouter()

	const handleOpacityChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
		setNewTantrum((prev) => ({
			...prev,
			opacity: parseFloat(e.target.value),
		}))
	}

	const handleGenerateGradient = (): void => {
		setNewTantrum((prev) => ({
			...prev,
			background: generateGradient(),
		}))
	}

	useEffect(() => {
		async function checkAuth(): Promise<void> {
			try {
				await fetch("/api/v1/me", {
					method: "GET",
					credentials: "include",
				})
					.then((r) => r.json())
					.then((r) => {
						if (!r.ok) {
							router.push("/login")
						} else {
							setLoggedIn(true)
							setUsername(r?.data?.username)
						}
					})
			} catch {}
		}

		checkAuth()
	}, [router])

	useEffect(() => {
		async function getTantrums(): Promise<void> {
			try {
				const response = await fetch("/api/v1/tantrums", {
					method: "GET",
					credentials: "include",
				}).then((r) => r.json())

				if (response.ok) {
					setTantrums(response.data)
				} else {
					setError("Failed to fetch tantrums")
				}
			} catch (error) {
				console.error(error)
				setError("An error occurred while fetching tantrums")
			}
		}

		getTantrums()
	}, [loggedIn])

	const handleSubmit = async (e: FormEvent<HTMLFormElement>): Promise<void> => {
		e.preventDefault()

		try {
			const temp = newTantrum

			const response = await fetch("/api/v1/tantrums", {
				method: "POST",
				headers: {
					"Content-Type": "application/json",
				},
				body: JSON.stringify(temp),
			})

			if (response.ok) {
				const newTantrumResponse = await response.json()
				setTantrums([...tantrums, newTantrumResponse.data])
				setNewTantrum({
					isPrivate: newTantrum.isPrivate,
					background: newTantrum.background ?? generateGradient(),
					opacity: newTantrum.opacity ?? 0.9,
				})
			} else {
				const data = await response.json()
				setError(data.error || "Failed to create tantrum")
			}
		} catch (error) {
			console.error(error)
			setError("An error occurred while creating a new tantrum")
		}
	}

	const handleDelete = async (_id: string): Promise<void> => {
		try {
			const response = await fetch(`/api/v1/tantrums/${btoa(_id)}`, {
				method: "DELETE",
			})

			if (response.ok) {
				setTantrums(tantrums.filter((t) => t._id !== _id))
			} else {
				setError("Failed to delete tantrum")
			}
		} catch (error) {
			console.error(error)
			setError("An error occurred while deleting the tantrum")
		}
	}

	return (
		<div className="flex min-h-screen flex-col bg-gray-100">
			<Header showDiscover={true} showLogout={true} showProfile={username} />

			<div className="relative mx-auto my-32 flex h-[75vh] w-full max-w-6xl items-center justify-center">
				<div className="relative flex min-w-fit justify-between gap-16 rounded-[2rem] bg-white p-12 shadow-xl">
					<div>
						<div className="absolute left-0 right-0 top-0 h-24 rounded-t-[2rem] bg-gradient-to-b from-white/90 to-white/20" />
						<h2 className="mb-8 text-center text-3xl font-bold">Manage your tantrums</h2>
						{error && (
							<div className="rounded-md bg-red-50 p-4 text-center text-sm text-red-500">{error}</div>
						)}
						<form className="relative space-y-6" onSubmit={handleSubmit}>
							<div className="space-y-2">
								<label className="block font-mono text-sm" htmlFor="title">
									Title
								</label>
								<input
									type="text"
									id="title"
									value={newTantrum.title ?? ""}
									onChange={(e) => setNewTantrum({ ...newTantrum, title: e.target.value })}
									className="w-full rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 font-mono focus:border-purple-500 focus:outline-none"
									placeholder="Loving..Liar.."
									required
								/>
							</div>
							<div className="space-y-2">
								<label className="block font-mono text-sm" htmlFor="description">
									Description
								</label>
								<textarea
									id="description"
									value={newTantrum.description ?? ""}
									onChange={(e) => setNewTantrum({ ...newTantrum, description: e.target.value })}
									className="w-full rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 font-mono focus:border-purple-500 focus:outline-none"
									placeholder="What happened?"
									required
								/>
							</div>
							<div className="flex items-center justify-between space-x-2">
								<div className="flex items-center space-x-2">
									<input
										type="checkbox"
										id="isPrivate"
										checked={newTantrum.isPrivate || false}
										onChange={(e) => setNewTantrum({ ...newTantrum, isPrivate: e.target.checked })}
										className="h-4 w-4 rounded border-gray-300 text-purple-600 focus:ring-purple-500"
									/>
									<label className="font-mono text-sm" htmlFor="isPrivate">
										For my eyes alone
									</label>
								</div>
								<label className="block font-mono text-sm">Opacity</label>
							</div>
							<div className="space-y-2">
								<input
									type="range"
									min="0"
									max="1"
									step="0.1"
									value={newTantrum.opacity}
									onChange={handleOpacityChange}
									className="w-full"
								/>
							</div>
							<div
								className="h-20 w-full cursor-pointer rounded-lg"
								style={{ background: newTantrum.background, opacity: newTantrum.opacity }}
								onClick={handleGenerateGradient}
								title="Click to generate new gradient"
							/>
							<button
								type="submit"
								className="w-full rounded-lg bg-gradient-to-r from-purple-600 to-purple-700 px-4 py-3 font-bold text-white transition-colors hover:from-purple-700 hover:to-purple-800">
								Add Tantrum
							</button>
						</form>
					</div>

					{tantrums.length !== 0 && (
						<div>
							<table className="mt-8 w-full">
								<thead>
									<tr className="bg-gray-200">
										<th className="px-4 py-2 text-left">Title</th>
										<th className="px-4 py-2 text-left">Description</th>
										<th className="px-4 py-2 text-left">Date</th>
										<th className="px-4 py-2 text-left">Privacy</th>
										<th className="px-4 py-2 text-left">Actions</th>
									</tr>
								</thead>
								<tbody>
									{tantrums.map((tantrum) => (
										<tr key={tantrum._id} className="border-b">
											<td className="px-4 py-2">{tantrum.title.slice(0, 16)}</td>
											<td className="px-4 py-2">{(tantrum.description ?? "").slice(0, 24)}</td>
											<td className="px-4 py-2">{`${tantrum.date.split("T")[0]} ${tantrum.date.split("T")[1].split(".")[0]}`}</td>
											<td className="px-4 py-2">{tantrum.isPrivate ? "Private" : "Public"}</td>
											<td className="px-4 py-2">
												<button
													className="mr-2 rounded-lg bg-red-500 px-4 py-2 text-white hover:bg-red-600"
													onClick={() => handleDelete(tantrum._id)}>
													Delete
												</button>
											</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					)}
				</div>
			</div>

			<About />
			<Footer />
		</div>
	)
}

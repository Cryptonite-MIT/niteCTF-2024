"use client"

import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"

import { Tantrum } from "@/app/utils"
import About from "@/components/About"
import Bubble from "@/components/Bubble"
import Footer from "@/components/Footer"
import Header from "@/components/Header"

import { BubbleConfig, generateGradient, generateSize, generateTransform } from "../utils"

export default function Profile(): JSX.Element {
	const [users, setUsers] = useState<Tantrum[]>([])
	const [bubbles, setBubbles] = useState<BubbleConfig[]>([])
	const [loginChecked, setLoginChecked] = useState<boolean>(false)
	const [loggedIn, setLoggedIn] = useState<boolean>(false)
	const [username, setUsername] = useState<string>("")
	const [error, setError] = useState<string>("")
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
						setLoginChecked(true)
						if (r.ok) {
							setLoggedIn(true)
							setUsername(r.data.username)
						} else {
							router.push("/login")
						}
					})
			} catch {
				setLoginChecked(true)
			}
		}

		checkAuth()
	}, [router])

	useEffect(() => {
		async function getTantrums(): Promise<void> {
			try {
				const response = await fetch(`/api/v1/users`, {
					method: "GET",
					credentials: "include",
				}).then((r) => r.json())

				if (response.ok) {
					setUsers(response.data.map((user: string) => ({ title: user, description: "" })))
				} else {
					setError("Failed to fetch users")
				}
			} catch (error) {
				console.error(error)
				setError("Failed to fetch users")
			}
		}

		getTantrums()
	}, [loginChecked, loggedIn])

	useEffect(() => {
		const generatedBubbles = users.map((data, index) => {
			const size = generateSize()
			return {
				background: generateGradient(),
				opacity: 0.9,
				size: { width: size, height: size },
				position: generateTransform(index),
				title: data.title,
				description: data.description ?? "",
				zIndex: index === 0 ? 2 : undefined,
			}
		})
		setBubbles(generatedBubbles)
	}, [users])

	return (
		<div className="flex min-h-screen flex-col bg-gray-100">
			<Header
				autoHideHeader={true}
				showLogin={!loggedIn}
				showRegister={!loggedIn}
				showLogout={loggedIn}
				showEdit={loggedIn}
				editText={!users.length ? "Create your first tantrum!" : "Edit Tantrums"}
				username={username}
			/>
			<main className="flex flex-grow flex-col">
				<div className="bg-fafafa relative mx-auto h-[100vh] w-full overflow-hidden">
					{bubbles.map((bubble, index) => (
						<Bubble key={index} bubbleNumPt={0} onClick={`/${bubble.title}`} {...bubble} />
					))}
					{bubbles.length === 0 && (
						<div className="flex min-h-[100vh] items-center justify-center">{error}</div>
					)}
				</div>
			</main>
			<About />
			<Footer />
		</div>
	)
}

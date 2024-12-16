"use client"

import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"

import { Tantrum } from "@/app/utils"
import About from "@/components/About"
import Bubble from "@/components/Bubble"
import Footer from "@/components/Footer"
import Header from "@/components/Header"

import { BubbleConfig, generateGradient, generateSize, generateTransform } from "../utils"

export default function Profile({ params }: { params: { username: string } }): JSX.Element {
	const [tantrums, setTantrums] = useState<Tantrum[]>([])
	const [bubbles, setBubbles] = useState<BubbleConfig[]>([])
	const [loginChecked, setLoginChecked] = useState<boolean>(false)
	const [loggedIn, setLoggedIn] = useState<boolean>(false)
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
				const response = await fetch(`/api/v1/tantrums/get/${params.username}`, {
					method: "GET",
					credentials: "include",
				}).then((r) => r.json())

				if (response.ok) {
					setTantrums(response.data)
					if (response.data.length === 0) {
						setError(
							loginChecked
								? loggedIn
									? "It's looking pretty empty here. E v e r y o n e has someone to rant about."
									: "No tantrums found. This person might be quite a gem ;-?"
								: "Loading..."
						)
					}
				} else {
					setError("Profile not found")
				}
			} catch (error) {
				console.error(error)
				setError("Failed to fetch tantrums")
			}
		}

		getTantrums()
	}, [loginChecked, loggedIn])

	useEffect(() => {
		const generatedBubbles = tantrums.map((data, index) => {
			const size = generateSize()
			return {
				background: data.background ?? generateGradient(),
				opacity: data.opacity ?? generateGradient(),
				size: { width: size, height: size },
				position: generateTransform(index),
				title: data.title,
				description: data.description ?? "",
				zIndex: index === 0 ? 2 : undefined,
			}
		})
		setBubbles(generatedBubbles)
	}, [tantrums])

	return (
		<div className="flex min-h-screen flex-col bg-gray-100">
			<Header
				autoHideHeader={true}
				showDiscover={true}
				showLogin={!loggedIn}
				showRegister={!loggedIn}
				showLogout={loggedIn}
				showEdit={loggedIn}
				editText={!tantrums.length ? "Create your first tantrum!" : "Edit Tantrums"}
				username={params.username}
			/>
			<main className="flex flex-grow flex-col">
				<div className="bg-fafafa relative mx-auto h-[100vh] w-full overflow-hidden">
					{bubbles.map((bubble, index) => (
						<Bubble key={index} {...bubble} />
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

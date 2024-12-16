"use client"

import { useRouter } from "next/navigation"
import { useEffect, useState } from "react"

import About from "@/components/About"
import Bubble from "@/components/Bubble"
import Footer from "@/components/Footer"
import Header from "@/components/Header"
import tantrums from "@/lib/initTantrums.json"

import { BubbleConfig, generateGradient, generateSize, generateTransform } from "./utils"

export default function Home(): JSX.Element {
	const [bubbles, setBubbles] = useState<BubbleConfig[]>([])
	const [loggedIn, setLoggedIn] = useState<boolean>(false)
	const [username, setUsername] = useState<string>("")
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
							setLoggedIn(true)
							setUsername(r?.data?.username)
						}
					})
			} catch {}
		}

		checkAuth()
	}, [router])

	useEffect(() => {
		const generatedBubbles = tantrums.map((data, index) => {
			const size = generateSize()
			return {
				background: generateGradient(),
				size: { width: size, height: size },
				position: generateTransform(index),
				title: data.title,
				description: data.description,
				zIndex: index === 0 ? 2 : undefined,
			}
		})
		setBubbles(generatedBubbles)
	}, [])

	return (
		<div className="flex min-h-screen flex-col bg-gray-100">
			<Header
				autoHideHeader={true}
				showDiscover={true}
				showLogin={!loggedIn}
				showRegister={!loggedIn}
				showLogout={loggedIn}
				showProfile={username}
			/>
			<main className="flex flex-grow flex-col">
				<div className="bg-fafafa relative mx-auto h-[100vh] w-full overflow-hidden">
					{bubbles.map((bubble, index) => (
						<Bubble key={index} {...bubble} />
					))}
				</div>
			</main>
			<About />
			<Footer />
		</div>
	)
}

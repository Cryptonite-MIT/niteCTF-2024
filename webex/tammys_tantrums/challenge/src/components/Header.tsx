"use client"

import Link from "next/link"
import { useEffect, useRef } from "react"

interface HeaderProps {
	autoHideHeader?: boolean
	showHome?: boolean
	showDiscover?: boolean
	showProfile?: string
	showLogin?: boolean
	showRegister?: boolean
	showLogout?: boolean
	showEdit?: boolean
	editText?: string
	username?: string
}

export default function Header({
	autoHideHeader,
	showHome,
	showDiscover,
	showProfile,
	showLogin,
	showRegister,
	showLogout,
	showEdit,
	editText,
	username,
}: HeaderProps): JSX.Element {
	const headerRef = useRef<HTMLElement>(null)
	let timeoutId: NodeJS.Timeout

	useEffect((): (() => void) => {
		if (!autoHideHeader) {
			// eslint-disable-next-line @typescript-eslint/no-empty-function
			return (): void => {}
		}

		const handleMouseMove = (): void => {
			if (headerRef.current) {
				headerRef.current.style.display = "flex"
				clearTimeout(timeoutId)
				timeoutId = setTimeout((): void => {
					if (headerRef.current) {
						headerRef.current.style.display = "none"
					}
				}, 2000)
			}
		}

		document.addEventListener("mousemove", handleMouseMove)
		return (): void => {
			document.removeEventListener("mousemove", handleMouseMove)
			clearTimeout(timeoutId)
		}
	}, [])

	return (
		<header
			ref={headerRef}
			className={`${autoHideHeader ? "fixed left-0 right-0 top-0 z-10 hidden transition-all" : "flex bg-white"} flex-col justify-between p-4 md:flex-row`}>
			<Link href="/" className="text-lg font-bold hover:underline">
				{username ?? "Tammy"}'s Tantrums
			</Link>
			<div className="relative mr-4 flex gap-8">
				{showDiscover && (
					<Link href={`/discover`} className="transition-all hover:underline">
						Discover
					</Link>
				)}
				{showProfile && (
					<Link href={`/${showProfile}`} className="transition-all hover:underline">
						{showProfile}
					</Link>
				)}
				{showLogin && (
					<Link href="/login" className="transition-all hover:underline">
						Login
					</Link>
				)}
				{showRegister && (
					<Link href="/register" className="transition-all hover:underline">
						Register
					</Link>
				)}
				{showEdit && (
					<Link href="/tantrums" className="transition-all hover:underline">
						{editText ?? "Edit Tantrums"}
					</Link>
				)}
				{showHome && (
					<Link href="/" className="transition-all hover:underline">
						Home
					</Link>
				)}
				{showLogout && (
					<Link href="/logout" className="transition-all hover:underline">
						Logout
					</Link>
				)}
			</div>
		</header>
	)
}

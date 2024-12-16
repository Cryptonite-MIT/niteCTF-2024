import "../styles/globals.css"

import type { Metadata } from "next"
import { Space_Mono } from "next/font/google"

const spaceMono = Space_Mono({
	weight: ["400", "700"],
	subsets: ["latin"],
})

export const metadata: Metadata = {
	title: "Tammy's Tantrums",
	description: "A place where every tantrum is embraced and uniquely yours",
}

export default function RootLayout({ children }: { children: React.ReactNode }): JSX.Element {
	return (
		<html lang="en">
			<body className={`${spaceMono.className} relative min-h-screen bg-gray-100`}>{children}</body>
		</html>
	)
}

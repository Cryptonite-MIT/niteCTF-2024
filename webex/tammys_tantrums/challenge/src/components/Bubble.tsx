"use client"
import { useMemo } from "react"

interface BubbleProps {
	background: string
	size: {
		width: string
		height: string
	}
	position: {
		top?: string
		left?: string
		transform?: string
	}
	title: string
	description: string
	opacity?: number
	zIndex?: number
	bubbleNumPt?: 0
	onClick?: string
}

export default function Bubble({
	background,
	size,
	position,
	title,
	description,
	opacity = 0.9,
	zIndex = 1,
	bubbleNumPt,
	onClick,
}: BubbleProps): JSX.Element {
	const animationStyle = useMemo(() => {
		const randomAnimation = `wiggle${Math.floor(Math.random() * 15) + 1}`
		const randomDuration = 15 + Math.floor(Math.random() * 10)
		return {
			animation: `${randomAnimation} ${randomDuration}s linear infinite alternate`,
		}
	}, [])

	const sizeValue = parseFloat(size.width)
	const whiteOverlayStyle = {
		width: `${sizeValue * 1.1}em`,
		height: `${sizeValue * 0.5}em`,
	}
	const textStyles = {
		title: {
			fontSize: `${sizeValue * 0.2}em`,
		},
		description: {
			fontSize: `${sizeValue * 0.05}em`,
		},
	}

	const bubbleStyle = {
		...size,
		...position,
		background,
		opacity,
		zIndex,
		"--width": size.width,
		...animationStyle,
		cursor: onClick ? "pointer" : "default",
	} as React.CSSProperties

	const handleClick = (): void => {
		if (onClick) {
			window.location.href = onClick
		}
	}

	return (
		<div className="bubble" style={bubbleStyle} onClick={handleClick}>
			<div className="bubble-white" style={whiteOverlayStyle} />
			<div className="bubble-inner">
				<div className={`bubble-num pt-${bubbleNumPt ?? 2}`} style={textStyles.title}>
					{title.slice(0, 16)}
				</div>
				<div className="bubble-text" style={textStyles.description}>
					{description.slice(0, 24)}
				</div>
			</div>
		</div>
	)
}

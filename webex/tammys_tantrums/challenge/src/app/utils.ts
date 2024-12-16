export interface Tantrum {
	_id: string
	title: string
	description?: string
	date: string
	isPrivate: boolean
	background?: string
	opacity?: number
}

export interface BubbleConfig {
	background: string
	size: {
		width: string
		height: string
	}
	position: {
		top?: string
		left?: string
		transform: string
	}
	title: string
	description: string
	zIndex?: number
}

export interface TransformResult {
	top?: string
	left?: string
	transform: string
}

export const generateSize = (): string => {
	const size = 10 + Math.floor(Math.random() * 16)
	return `${size}rem`
}

export function generateHarmonicColor(baseHue: number): string {
	const hue = baseHue % 360
	const saturation = 65 + Math.random() * 20
	const lightness = 45 + Math.random() * 15
	return `hsl(${hue}, ${saturation}%, ${lightness}%)`
}

export function generateGradient(): string {
	const baseHue = Math.random() * 360
	const hueShift = 30 + Math.random() * 30
	const secondHue = (baseHue + hueShift) % 360
	const color1 = generateHarmonicColor(baseHue)
	const color2 = generateHarmonicColor(secondHue)
	return `linear-gradient(${color1}, ${color2})`
}

export function generateTransform(index: number): TransformResult {
	if (index === 0) {
		return {
			top: "50%",
			left: "50%",
			transform: "translate(-50%, -50%)",
		}
	}

	const x = -120 + Math.floor(Math.random() * 240)
	const y = -60 + Math.floor(Math.random() * 120)

	return {
		transform: `translate(${x}%, ${y}%)`,
	}
}

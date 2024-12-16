import mongoose, { Schema } from "mongoose"

export interface ITantrum {
	_id: string
	title: string
	description: string
	userId: string
	date: string
	isPrivate: boolean
	background?: string
	opacity?: number
}

const tantrumSchema = new Schema<ITantrum>(
	{
		_id: {
			type: String,
			required: true,
			default: (): string => new mongoose.Types.ObjectId().toString(),
		},
		title: {
			type: String,
			required: true,
		},
		description: {
			type: String,
			required: true,
		},
		userId: {
			type: String,
			required: true,
		},
		date: {
			type: String,
			required: true,
		},
		isPrivate: {
			type: Boolean,
			required: true,
			default: true,
		},
		background: {
			type: String,
			required: false,
		},
		opacity: {
			type: Number,
			required: false,
		},
	},
	{
		timestamps: true,
	}
)

export default mongoose.models.Tantrum || mongoose.model<ITantrum>("Tantrum", tantrumSchema)

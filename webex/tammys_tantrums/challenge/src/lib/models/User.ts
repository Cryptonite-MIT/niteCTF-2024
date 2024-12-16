import mongoose, { Schema } from "mongoose"

import { ITantrum } from "@/lib/models/Tantrum"

export interface IUser {
	username: string
	password: string
	tantrums: ITantrum[]
	createdAt: Date
	updatedAt: Date
}

const userSchema = new Schema<IUser>(
	{
		username: {
			type: String,
			required: true,
			unique: true,
			trim: true,
			minlength: 3,
		},
		password: {
			type: String,
			required: true,
		},
		tantrums: [
			{
				type: String,
				ref: "Tantrum",
			},
		],
	},
	{
		timestamps: true,
	}
)

export default mongoose.models.User || mongoose.model<IUser>("User", userSchema)

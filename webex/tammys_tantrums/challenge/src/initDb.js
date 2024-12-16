const fs = require("fs")
const path = require("path")

const BASE_URL = "http://localhost:3000/api/v1"
const FLAG = process.env.FLAG ?? "nite{fake_flag}"
const USERNAME = "tammy"

async function generateRandomPassword() {
    const array = new Uint8Array(32)
    crypto.getRandomValues(array)
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("")
}

async function setup() {
    try {
        await new Promise(resolve => setTimeout(resolve, 5000));

        const username = USERNAME

        const password = await generateRandomPassword()
        console.log(`Generated password for ${username}:`, password)

        const registerResponse = await fetch(`${BASE_URL}/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username,
                password,
            }),
        })

        if (!registerResponse.ok) {
            throw new Error(`Registration failed: ${await registerResponse.text()}`)
        }
        console.log(`Created user: ${username}`)

        const loginResponse = await fetch(`${BASE_URL}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                username,
                password,
            }),
        })

        if (!loginResponse.ok) {
            throw new Error(`Login failed: ${await loginResponse.text()}`)
        }

        const cookies = loginResponse.headers.get("set-cookie")
        const token = cookies.split(";")[0]

        const tantrumData = JSON.parse(fs.readFileSync(path.join(process.cwd(), "lib", "initTantrums.json"), "utf8"))
        tantrumData.push({
            title: "flag",
            description: FLAG,
            isPrivate: true,
        })

        for (const tantrum of tantrumData) {
            const createResponse = await fetch(`${BASE_URL}/tantrums`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Cookie: token,
                },
                body: JSON.stringify({
                    title: tantrum.title,
                    description: tantrum.description,
                    isPrivate: tantrum.isPrivate || false,
                }),
            })

            if (!createResponse.ok) {
                throw new Error(`Failed to create tantrum: ${await createResponse.text()}`)
            }
            console.log(`Created tantrum: ${tantrum.title}`)
        }

        console.log("Setup completed successfully")
    } catch (error) {
        console.error("Setup failed:", error)
        process.exit(1)
    }
}

setup()

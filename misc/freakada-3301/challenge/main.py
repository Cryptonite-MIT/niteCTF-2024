from typing import Final
import os
import asyncio
from dotenv import load_dotenv
from discord import Intents, Client, Message
from responses import get_response
import random

load_dotenv()
TOKEN: Final[str] = os.getenv('DISCORD_TOKEN')
if not TOKEN:
    raise ValueError("DISCORD_TOKEN is not set in the environment variables")

# connecting the bot / setting bro up
intents: Intents = Intents.default()
intents.message_content = True  # NOQA
client: Client = Client(intents=intents)

# MESSAGE FUNCTIONALITY


async def send_message(message: Message, user_message: str, channel: str) -> None:
    private_talk: bool = False
    if not user_message:
        print('empty message. no intents.')
        return
    else:
        private_talk: bool = True
        try:
            response: str = await get_response(user_message, private_talk)
            await message.channel.send(response, silent=True)
        except Exception as e:
            print(e)


@client.event
async def on_ready() -> None:
    print(f'{client.user} is up')


@client.event
async def on_message(message: Message) -> None:
    if message.author == client.user:
        return

    username: str = str(message.author)
    user_message: str = message.content
    channel: str = str(message.channel)

    print(f'[{channel}] {username}: "{user_message}"')
    if channel == "Direct Message with Unknown User":
        await send_message(message, user_message, channel)
    else:
        pass


def main() -> None:
    client.run(token=TOKEN)


if __name__ == '__main__':
    main()

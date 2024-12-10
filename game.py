import pygame
import random

# Initialize pygame
pygame.init()

# Game settings
WIDTH, HEIGHT = 600, 600
FPS = 30
TILE_SIZE = 30
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
YELLOW = (255, 255, 0)
RED = (255, 0, 0)
GREEN = (0, 255, 0)
BLUE = (0, 0, 255)

# Setup the game screen
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Pac-Man")

# Define directions
UP = (0, -TILE_SIZE)
DOWN = (0, TILE_SIZE)
LEFT = (-TILE_SIZE, 0)
RIGHT = (TILE_SIZE, 0)

# Create the player class (Pac-Man)
class PacMan:
    def __init__(self):
        self.x = WIDTH // 2
        self.y = HEIGHT // 2
        self.size = TILE_SIZE
        self.direction = RIGHT
        self.speed = TILE_SIZE

    def move(self):
        self.x += self.direction[0]
        self.y += self.direction[1]

    def draw(self):
        pygame.draw.circle(screen, YELLOW, (self.x + TILE_SIZE // 2, self.y + TILE_SIZE // 2), TILE_SIZE // 2)

# Create the Ghost class
class Ghost:
    def __init__(self, color, x, y):
        self.x = x
        self.y = y
        self.size = TILE_SIZE
        self.color = color
        self.direction = random.choice([UP, DOWN, LEFT, RIGHT])

    def move(self):
        self.x += self.direction[0]
        self.y += self.direction[1]

    def draw(self):
        pygame.draw.circle(screen, self.color, (self.x + TILE_SIZE // 2, self.y + TILE_SIZE // 2), TILE_SIZE // 2)

# Create some walls for the maze
def draw_walls():
    for i in range(0, WIDTH, TILE_SIZE):
        pygame.draw.rect(screen, BLUE, (i, 0, TILE_SIZE, TILE_SIZE))
        pygame.draw.rect(screen, BLUE, (i, HEIGHT - TILE_SIZE, TILE_SIZE, TILE_SIZE))
    for i in range(0, HEIGHT, TILE_SIZE):
        pygame.draw.rect(screen, BLUE, (0, i, TILE_SIZE, TILE_SIZE))
        pygame.draw.rect(screen, BLUE, (WIDTH - TILE_SIZE, i, TILE_SIZE, TILE_SIZE))

def main():
    clock = pygame.time.Clock()
    pacman = PacMan()
    ghosts = [Ghost(RED, random.randint(0, (WIDTH // TILE_SIZE) - 1) * TILE_SIZE, random.randint(0, (HEIGHT // TILE_SIZE) - 1) * TILE_SIZE) for _ in range(3)]

    # Main game loop
    running = True
    while running:
        clock.tick(FPS)

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                running = False

        # Get pressed keys
        keys = pygame.key.get_pressed()

        # Control Pac-Man
        if keys[pygame.K_UP]:
            pacman.direction = UP
        if keys[pygame.K_DOWN]:
            pacman.direction = DOWN
        if keys[pygame.K_LEFT]:
            pacman.direction = LEFT
        if keys[pygame.K_RIGHT]:
            pacman.direction = RIGHT

        # Move pacman and ghosts
        pacman.move()
        for ghost in ghosts:
            ghost.move()

        # Draw everything
        screen.fill(BLACK)
        draw_walls()
        pacman.draw()
        for ghost in ghosts:
            ghost.draw()

        pygame.display.flip()

    pygame.quit()

if __name__ == "__main__":
    main()

import pygame

colors = [
    (0, 0, 0),
    (0, 0, 0),
    (255, 255, 255)
]
b_counter = 0
pre_blocks = [(0,1), (4,1), (0,2), (6,1), (7,2), (5,1), (3,2), (7,1), (7,1), (7,1), 
              (2,2), (7,2), (7,1), (7,1), (7,2), (7,1), (2,2), (7,2), (7,2), (7,1),
              (7,1), (7,2), (5,2), (5,1), (4,2), (7,2), (7,1), (7,2), (7,2), (7,2), 
              (7,1), (6,1), (5,2), (0,1), (2,1), (7,1), (7,2), (7,1), (7,1), (5,2),
              (7,1), (7,1), (7,1), (5,2), (7,1), (1,2), (4,2), (6,2), (3,1), (4,2),
              (0,1), (0,2), (0,2), (0,2), (6,1), (3,1), (7,1), (0,2), (0,1), (4,1),
              (0,1), (3,2), (5,2), (0,1), (7,2), (7,2), (7,1), (7,2), (7,2), (7,1),
              (5,2), (1,1), (7,1), (7,1), (7,2), (7,2), (7,1), (1,2), (7,1), (7,1),
              (7,2), (7,2), (3,2), (7,1), (0,1), (3,1), (3,2), (7,1), (7,1), (0,1),
              (5,1), (0,1), (4,2), (7,1), (4,2), (7,1), (7,2), (7,1), (2,2), (3,1),
              (3,1), (7,2), (6,1), (7,2), (7,2), (7,2), (7,2), (7,1), (7,1), (1,1),
              (3,1), (7,2), (7,2), (7,2), (7,2), (7,1), (7,1), (7,2), (7,2), (1,1),
              (4,2), (7,2), (4,2), (5,1), (5,2), (7,2), (7,2), (7,2), (7,2), (7,2),
              (5,1), (7,2), (5,1), (6,1), (6,1), (7,1), (7,1), (7,1), (7,1), (7,1),
              (6,1), (6,1), (0,1), (3,1), (6,2), (7,1), (7,1), (7,2), (7,2), (4,2),
              (2,1), (7,2), (7,2), (1,2), (7,1), (7,1), (5,1), (1,2), (7,1), (7,2),
              (4,2), (5,1), (3,1), (2,2), (7,2), (7,2), (7,1), (7,2), (7,1), (7,1),
              (7,2), (2,2), (7,1), (7,1), (1,2), (5,1), (7,1), (7,2), (7,2), (7,1), 
              (7,1), (7,1), (7,1), (7,1), (7,1), (7,2), (1,2), (7,1), (7,2), (7,2),
              (7,1), (7,1), (7,2), (4,2), (7,2), (7,2), (7,2), (4,1), (7,2), (4,2),
              (0,2), (3,1), (3,1), (6,1), (6,1), (4,1), (5,1), (7,2), (7,2), (7,2),
              (7,2), (7,2), (7,2), (7,1), (7,2), (7,2), (7,2), (6,1), (7,2), (7,2),
              (7,1), (7,1), (7,1), (0,1), (3,2), (0,2), (7,1), (7,1), (7,1), (7,2),
              (2,1), (2,2), (5,1), (7,1), (7,1), (7,1), (7,1), (7,1), (7,1), (7,1),
              (7,1), (7,2), (7,2), (7,2), (7,2), (7,2), (7,2), (7,2), (7,2), (5,1),
              (7,1), (6,1), (7,1), (7,2), (5,2), (7,1), (4,2), (4,1), (5,2), (7,2),
              (7,2), (7,2), (5,1), (5,1), (4,2), (7,1), (7,1), (7,1), (7,1), (7,2),
              (0,1), (3,2), (7,1), (7,1), (7,2), (7,1), (1,2), (0,1), (4,2), (7,1),
              (7,1), (5,2), (7,1), (7,2), (7,2), (7,1), (5,2), (7,2), (6,1), (7,2), 
              (7,1), (7,1), (7,1), (7,2), (7,2), (7,2), (5,2), (6,1), (4,2), (7,2), 
              (7,2), (7,2), (7,1), (0,1), (7,1), (7,2), (5,1), (4,2), (5,2), (4,2),
              (7,1), (5,2), (4,1), (4,1), (7,2), (7,2), (7,2), (2,2), (7,2), (4,2),
              (6,1), (6,1), (7,1), (7,1), (7,1), (7,1), (7,1), (7,2), (7,2), (1,1),
              (7,2), (7,1), (7,1), (6,2), (7,1), (5,2), (1,1), (7,2), (7,1), (5,2),
              (7,1), (0,1), (5,1), (7,2), (7,2), (7,2), (7,2), (7,2), (7,1), (0,1),
              (7,1), (5,1), (1,1), (7,1), (7,2), (7,2), (7,2), (4,2), (5,2), (7,1),
              (7,1), (5,1), (7,2), (7,2), (3,2), (7,1), (7,2)
              ]

class Figure:
    x = 0
    y = 0

    figures = [
        [[1, 5, 9, 13], [4, 5, 6, 7]],                                  # I block 
        [[4, 5, 9, 10], [2, 6, 5, 9]],                                  # Z block
        [[6, 7, 9, 10], [1, 5, 6, 10]],                                 # S block
        [[1, 2, 5, 9], [0, 4, 5, 6], [1, 5, 9, 8], [4, 5, 6, 10]],      # J block
        [[1, 2, 6, 10], [5, 6, 7, 9], [2, 6, 10, 11], [3, 5, 6, 7]],    # L block
        [[1, 4, 5, 6], [1, 4, 5, 9], [4, 5, 6, 9], [1, 5, 6, 9]],       # T block
        [[1, 2, 5, 6]],                                                 # O block                 
        [[1, 1, 1, 1]]                                                  # Cheat block
    ]

    def __init__(self, type, color):
        self.x = 15
        self.y = 0
        self.type = type
        self.color = color
        self.rotation = 0

    def image(self):
        return self.figures[self.type][self.rotation]

    def rotate(self):
        self.rotation = (self.rotation + 1) % len(self.figures[self.type])


class Tetris:
    def __init__(self, height, width):
        self.level = 2
        self.score = 0
        self.state = "start"
        self.field = []
        self.height = 0
        self.width = 0
        self.x = 100
        self.y = 60
        self.zoom = 20
        self.figure = None
    
        self.height = height
        self.width = width
        self.field = []
        self.score = 0
        self.state = "start"
        for i in range(height):
            new_line = []
            for j in range(width):
                new_line.append(0)
            self.field.append(new_line)

    def new_figure(self, counter):
        global b_counter
        b_counter = counter
        while b_counter < len(pre_blocks):
            a, b = pre_blocks[b_counter]
            b_counter += 1
            self.figure = Figure(a, b)
            return

        self.figure = Figure(0, 0)
    def intersects(self):
        intersection = False
        for i in range(4):
            for j in range(4):
                if i * 4 + j in self.figure.image():
                    if i + self.figure.y > self.height - 1 or \
                            j + self.figure.x > self.width - 1 or \
                            j + self.figure.x < 0 or \
                            self.field[i + self.figure.y][j + self.figure.x] > 0:
                        intersection = True
        return intersection

    def break_lines(self):
        lines = 0
        for i in range(1, self.height):
            zeros = 0
            for j in range(self.width):
                if self.field[i][j] == 0:
                    zeros += 1
            if zeros == 0:
                lines += 1
                for i1 in range(i, 1, -1):
                    for j in range(self.width):
                        self.field[i1][j] = self.field[i1 - 1][j]
        self.score += lines ** 2

    def go_space(self):
        while not self.intersects():
            self.figure.y += 1
        self.figure.y -= 1
        self.freeze()

    def go_down(self):
        self.figure.y += 1
        if self.intersects():
            self.figure.y -= 1
            self.freeze()

    def freeze(self):
        for i in range(4):
            for j in range(4):
                if i * 4 + j in self.figure.image():
                    self.field[i + self.figure.y][j + self.figure.x] = self.figure.color
        self.break_lines()
        self.new_figure(b_counter)
        if self.intersects():
            self.state = "gameover"

    def go_side(self, dx):
        old_x = self.figure.x
        self.figure.x += dx
        if self.intersects():
            self.figure.x = old_x

    def rotate(self):
        old_rotation = self.figure.rotation
        self.figure.rotate()
        if self.intersects():
            self.figure.rotation = old_rotation



pygame.init()


BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GRAY = (128, 128, 128)
RED = (180, 180, 0)
size = (810, 910)
screen = pygame.display.set_mode(size)

pygame.display.set_caption("Tetris")



done = False
clock = pygame.time.Clock()
fps = 1
game = Tetris(40, 34)
counter = 0

pressing_down = False

while not done:
    if game.figure is None:
        game.new_figure(b_counter) 
    counter += 1
    if counter > 100000:
        counter = 0

    if counter % ( game.level // 2) == 0 or pressing_down:
        if game.state == "start":
            game.go_down()
            pass

    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            done = True
        if event.type == pygame.KEYDOWN:
            if event.key == pygame.K_w:
                game.rotate()
            if event.key == pygame.K_s:
                game.go_down()
            if event.key == pygame.K_a:
                game.go_side(-1)
            if event.key == pygame.K_d:
                game.go_side(1)
            if event.key == pygame.K_SPACE:
                game.go_space()
            if event.key == pygame.K_ESCAPE:
                game.__init__(810, 910)

    if event.type == pygame.KEYUP:
            if event.key == pygame.K_DOWN:
                pressing_down = False

    screen.fill(RED)

    for i in range(game.height):
        for j in range(game.width):
            pygame.draw.rect(screen, GRAY, [game.x + game.zoom * j, game.y + game.zoom * i, game.zoom, game.zoom], 1)
            if game.field[i][j] > 0:
                pygame.draw.rect(screen, colors[game.field[i][j]],
                                 [game.x + game.zoom * j + 1, game.y + game.zoom * i + 1, game.zoom - 2, game.zoom - 1])

    if game.figure is not None:
        for i in range(4):
            for j in range(4):
                p = i * 4 + j
                if p in game.figure.image():
                    pygame.draw.rect(screen, colors[game.figure.color],
                                     [game.x + game.zoom * (j + game.figure.x) + 1,
                                      game.y + game.zoom * (i + game.figure.y) + 1,
                                      game.zoom - 2, game.zoom - 2])

    font = pygame.font.SysFont('Calibri', 25, True, False)
    font1 = pygame.font.SysFont('Calibri', 65, True, False)
    text = font.render("Score: " + str(game.score), True, BLACK)
    text_game_over = font1.render("Game Over", True, (255, 125, 0))
    text_game_over1 = font1.render("Press ESC", True, (255, 215, 0))

    screen.blit(text, [0, 0])
    if game.state == "gameover":
        screen.blit(text_game_over, [20, 200])
        screen.blit(text_game_over1, [25, 265])

    pygame.display.flip()

    clock.tick(fps)

pygame.quit()

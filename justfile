# Substitution Cipher Solver - Task Automation
# Run `just` to list available recipes.

# Require bun: https://bun.sh
bun := require("bun")

# List available recipes
@default:
    just --list

# Start the local development server (http://localhost:3000)
dev *args:
    bun run server.ts {{ args }}
alias start := dev
alias s := dev

# Run unit tests
test *args:
    bun test {{ args }}
alias t := test

# Run unit tests in watch mode
test-watch:
    bun test --watch
alias tw := test-watch

# Install project dependencies
install:
    bun install
alias i := install

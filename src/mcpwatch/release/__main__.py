"""Entry point so ``python -m mcpwatch.release`` works."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())

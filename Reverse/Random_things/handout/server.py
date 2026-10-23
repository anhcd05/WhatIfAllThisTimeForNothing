#!/usr/bin/env python3

import os
import subprocess
import sys

CHECKER = "./checker"
SIDE_LENGTH = 21
TIMEOUT = 5

FLAG = os.environ["FLAG"]

BANNER = r"""
        Cubism Gallery

              ███
          ███ ███ ███
      ███ ███ ███ ███ ███
          ███ ███ ███
              ███

   A painting is more than the sum of its blocks.
"""


def reject() -> None:
    print("The curator studies your work for a moment.")
    print("Not quite a masterpiece.")
    sys.exit(1)


def main() -> None:
    print(BANNER)
    print("Welcome, artist.")
    print("Submit your cubist painting below.")
    print("The curator will begin after the final row.")
    print()

    painting = b"".join(
        sys.stdin.buffer.readline(SIDE_LENGTH + 2)
        for _ in range(SIDE_LENGTH * SIDE_LENGTH)
    )

    try:
        result = subprocess.run(
            [CHECKER],
            input=painting,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=TIMEOUT,
            check=False,
            env={},
        )
    except subprocess.TimeoutExpired:
        reject()

    if result.returncode != 0:
        reject()

    print("The curator smiles.")
    print("Correct!")
    print("")
    print(f"Enjoy your flag: {FLAG}")


if __name__ == "__main__":
    main()

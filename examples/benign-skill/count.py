import sys
from pathlib import Path


def main(path: str) -> None:
    text = Path(path).read_text(encoding="utf-8")
    words = text.split()
    sentences = [s for s in text.replace("!", ".").replace("?", ".").split(".") if s.strip()]
    avg = len(words) / len(sentences) if sentences else 0
    print(f"words: {len(words)}")
    print(f"characters: {len(text)}")
    print(f"avg sentence length: {avg:.1f} words")


if __name__ == "__main__":
    main(sys.argv[1])

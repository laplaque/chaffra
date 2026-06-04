import os
from pathlib import Path

def main():
    """Entry point."""
    p = Path(".")
    print(p)

def _unused_helper():
    """This is private and never called."""
    pass

class UsedClass:
    def method(self):
        pass

class _UnusedClass:
    def method(self):
        pass

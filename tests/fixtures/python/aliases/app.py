import os
import numpy as np
from pathlib import Path
from os.path import join as path_join

def main():
    arr = np.array([1, 2, 3])
    p = path_join("/tmp", "file.txt")
    print(arr, p)

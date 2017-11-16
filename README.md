# Wiedergänger

## Material
This repository contains supporting material for the paper `Dynamic Loader
oriented Programming on Linux`:

* The paper itself
* The slide deck as presented at ROOTS 2017
* A poster highlighting some details
* `simple.py`: A python script that bootstraps an attack succeeding with
  probability 1:4096 against weak ASLR implementations
* `strong.py`: A python script that bootstraps an attack succeeding with
  probability 1:1 against weak ASLR implementations

## Summary
The central point of all the documents is to
show that Linux currently (November 2017, kernel 4.14) uses a weak `mmap`
implementation that maps chunks at constant distances to each other into the
virtual address space. To show that this can be problematic, we developed two
attacks that show how to escalate Array-Out-of-Bounds-Writes to code execution by overwriting internal data structures used by `ld.so`.

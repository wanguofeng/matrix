#!/bin/bash
gcc example/1.c -I. -lunqlite -L. -o example_1
gcc example/2.c -I. -lunqlite -L. -o example_2
gcc example/3.c -I. -lunqlite -L. -o example_3
gcc example/4.c -I. -lunqlite -L. -o example_4
gcc example/5.c -I. -lunqlite -L. -o example_5
gcc example/6.c -I. -lunqlite -L. -o example_6
gcc example/demovfs/unqlite_demovfs.c -I. -lunqlite -L. -o unqlite_demovfs
gcc example/unqlite_huge.c -I. -lunqlite -L. -o unqlite_huge
gcc example/unqlite_mp3.c -I. -lunqlite -L. -o unqlite_mp3
gcc example/unqlite_tar.c -I. -lunqlite -L. -o unqlite_tar

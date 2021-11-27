all: compile

compile:
	gcc -ggdb -O0 test_mmap.c -o test_mmap
	gcc -ggdb -O0 test_create_write.c -o test_create_write
	gcc -ggdb -O0 test_read.c -o test_read -L./libfs/build/ -Wl,-rpath=./libfs/build/ -lmlfs -I./libfs/src
	gcc -ggdb -O0 test_mmap_read.c -o test_mmap_read -L./libfs/build/ -Wl,-rpath=./libfs/build/ -lmlfs -I./libfs/src
	gcc -ggdb -O0 test_mmap_write.c -o test_mmap_write -L./libfs/build/ -Wl,-rpath=./libfs/build/ -lmlfs -I./libfs/src
	gcc -ggdb -O0 test_create_non_cont_file.c -o test_create_non_cont_file -L./libfs/build/ -Wl,-rpath=./libfs/build/ -lmlfs -I./libfs/src
	gcc -ggdb -O0 test_mmap_read.c -o test_mmap_read -L./libfs/build/ -Wl,-rpath=./libfs/build/ -lmlfs -I./libfs/src
	gcc -ggdb -O0 test_read_mmap_non_cont_file.c -o test_read_mmap_non_cont_file -L./libfs/build/ -Wl,-rpath=./libfs/build/ -lmlfs -I./libfs/src

run: compile
	@echo "--------------------------------------- File create with 'aaaaa' as content without mmap ---------------------------------------"
	LD_PRELOAD=/home/ubuntu/assise_dc/libfs/build/libmlfs.so ./test_create_write
	@echo "------------------------------------------------------------------------------------------"
	@echo "--------------------------------------- First read without mmap ---------------------------------------"
	MLFS_DISABLE_INIT=1 ./test_read
	@echo "------------------------------------------------------------------------------------------"
	@echo "--------------------------------------- Replacing first char now using mmap ---------------------------------------"
	MLFS_DISABLE_INIT=1 ./test_mmap_write
	@echo "--------------------------------------------------------------------------------------------------------"
	@echo "--------------------------------------- Second Read without mmap ---------------------------------------"
	MLFS_DISABLE_INIT=1 ./test_read
	@echo "-------------------------------------------------------------------------------------------"
	@echo "--------------------------------------- Third Read with mmap ---------------------------------------"
	MLFS_DISABLE_INIT=1 ./test_mmap_read
	@echo "-------------------------------------------------------------------------------------------"
	# MLFS_DISABLE_INIT=1 gdb ./test_read
	# gdb ./test_read
	# LD_PRELOAD=/home/ubuntu/assise_dc/libfs/build/libmlfs.so ./test_read
	# LD_PRELOAD=/home/ubuntu/assise_dc/libfs/build/libmlfs.so ./a.out
	# ./a.out

debug: compile
	MLFS_DISABLE_INIT=1 ./test_create_non_cont_file
	# MLFS_DISABLE_INIT=1 gdb -x gdb_cmds ./test_read_mmap_non_cont_file
	MLFS_DISABLE_INIT=1 ./test_read_mmap_non_cont_file

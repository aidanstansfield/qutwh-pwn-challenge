all:
	gcc -m32 -g -w -no-pie -fno-stack-protector -o challenge challenge.c
clean:
	rm challenge


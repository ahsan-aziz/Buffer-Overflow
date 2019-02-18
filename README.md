# Buffer Overflow With an Example

To understand Buffer Overflow we need to uderstand the memory layout of the program. When we run a typical C program, it gets loaded to the memory (RAM) and gets divided into following five segments ([more here](http://www.cis.syr.edu/~wedu/seed/Book/book_sample_buffer.pdf)):

- **Text**: stores the executable code of the program.
- **Initialized data**: stores static/global variables. 
- **Uninitialized data(BSS)**: stores uninitialized static/global variables. 
- **Heap**: This is for dynamic memory allocation, it can be managed using functions like malloc, calloc, realloc, free, etc.
- **Stack**: It is used for storing local variables defined inside functions, along with data related to function calls.

![Memory Layout](https://github.com/azizahsan/Buffer-Overflow/blob/master/Memory%20layout.png?raw=true)

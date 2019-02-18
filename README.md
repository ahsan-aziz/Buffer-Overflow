# Buffer Overflow With an Example

To understand Buffer Overflow we need to uderstand the memory layout of the program. When we run a typical C program, it gets loaded into the memory (RAM) and gets divided into following five segments ([more here](http://www.cis.syr.edu/~wedu/seed/Book/book_sample_buffer.pdf)):

- **Text**: stores the executable code of the program.
- **Initialized data**: stores static/global variables. 
- **Uninitialized data(BSS)**: stores uninitialized static/global variables. 
- **Heap**: It is for dynamic memory allocation, it can be managed using functions like malloc, calloc, realloc, free, etc.
- **Stack**: It is used for storing local variables defined inside functions, along with data related to function calls.

![Memory Layout](https://github.com/azizahsan/Buffer-Overflow/blob/master/layout.png?raw=true)

Please note that Stack grows higher to lower address and heap grows opposite. 

Let's take an example. Following is a small C-program:

```
int x = 1000;
int main()
{
int var1=2;
static int var2;

int *ptr = (int*) malloc(2 * sizeof(int));

ptr[0]=5;
ptr[1]=6;

free(ptr);

return 1;
}
```

The above program will be loaded in memory as follows:

Variable x (global variable) -> Initialized Data Segment (BSS)

Local variables var1 and ptr  -> Stack

Variable y -> Uninialized Data Segment

Values of ptr[1] and ptr[2] -> Heap

Machine code of the compiled program -> Text Segment


When we used the function malloc, it allocated memory (size of two integers) on Heap, and variable ptr is a pointer which is pointing to that block of memory. The ptr will be stored on Stack and values 5 and 6 will go to Heap.

Buffer overflow can happen on both Heap and Stack, and the exploitation is differen for both. In this post, our focus is on stack overflow. 

When a function is called inside a program, some space is allocated on top of the stack. Here is a simple function:


```
void aFunc(int a, int b)
{

int x = a+b;
int y = a*b;

}
```

The above function will look like this in stack:
![function](https://github.com/azizahsan/Buffer-Overflow/blob/master/function.png?raw=true)
 
 Before we proceed we need to understand EBP. 
- Parameters: the arguments passed to the function will pushed first in the stack
- Return Address: when a funcion finishes it returns back to the callee function e.g. main function 
- Previous Frame pointer:  it is discussed below. 
- Local Variables: 

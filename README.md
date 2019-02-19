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

- Variable x (global variable) -> Initialized Data Segment (BSS)

- Local variables var1 and ptr  -> Stack

- Variable y -> Uninialized Data Segment

- Values of ptr[1] and ptr[2] -> Heap

- Machine code of the compiled program -> Text Segment


The function "malloc(2 * sizeof(int))" allocates memory (size of two integers) on Heap, and variable ptr is a pointer which is pointing to that block of memory. The ptr will be stored on Stack and values 5 and 6 will go to Heap.

Buffer overflow can happen on both Heap and Stack, and the exploitation is differen for both. In this post, our focus is on stack overflow. 

When a function is called inside a program, some space is allocated for it on top of the stack. Here is a simple function:


```
void aFunc(int a, int b)
{

int x = a+b;
int y = a*b;

}
```

The above function will look like this in stack:

![function](https://github.com/azizahsan/Buffer-Overflow/blob/master/function.png?raw=true)
 
- Parameters: the arguments passed to the function will be pushed first in the stack
- Return Address: when a funcion finishes it returns back to the callee function e.g. main function 
- Previous Frame pointer: it is discussed below. 
- Local Variables: next local variables are pushed to stack, the order of the variable is up to the compiler

**ESP and EBP Registers**:

When a program is loaded to the stack, ESP (Extended Stack Pointer) points to the top of the stack, remember stack grows from higher to lower address so ESP would be pointing to the lowest address in stack. We can access other parts of stack with the offset of ESP, e.g. in above example, the ESP would be pointing to the value of y and if value of x needed to be accessed we can add 4-bytes (in 32-bit architecture) in ESP and it would move to value of x. Now what if we call a function inside another function/porgram? the stack would grow to accomodate new function and ESP would also move to the top of the stack, and when we return from the function we would no longer able to access the stack segments as we haven't saved current value of ESP anywhere. To solve this problem, we have another register EBP (Extended Base Pointer), this register keeps the copy of ESP or just points to a fixed location in stack. We have two registers now, ESP pointing to the top of the stack, it can move freely as needed, and EBP which is pointing to a fixed location and other segments can be accessed with the offset of EBP. In this case, when we call another function, we can push the value of EBP into the stack of new function, so that when the function finishes we know get back our base pointer. The "Previous Frame Pointer" in above example is basically value of EBP from previous function.   

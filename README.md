# Buffer Overflow With an Example

To understand Buffer Overflow we need to uderstand the memory layout of the program. When we run a typical C program, it gets loaded into the memory (RAM) and gets divided into following five segments:

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

When a function is called inside a program, some space is reserved for it on top of the stack. For instance the following code:


```
#include <string.h>

void foo(int a, int b)
{

int x = a+b;
int y = a*b;

}
int main()
{
  foo(8,9);
  printf("program finishing")
  return 1;
}

```

The function "foo()" would look like this in stack:

![function](https://github.com/azizahsan/Buffer-Overflow/blob/master/function.png?raw=true)
 
- **Parameters**: the arguments passed to the function will be pushed first in the stack
- **Return Address**: when a funcion finishes, it returns back to the callee function and the address of next statement is called return address; in above example when foo() finishes it needs to return back to main() function, and run the statement right next to it, so the address of printf statement would be the return address. Please make sure you understand this as this is very important when we exploit buffer overflow.
- **Previous Frame pointer**: When a program is loaded to the stack, ESP (Extended Stack Pointer) points to the top of the stack, remember stack grows from higher to lower address so ESP would be pointing to the lowest address in stack. We can access other parts of stack with the offset of ESP, e.g. in above example, the ESP would be pointing to the value of y and if value of x needed to be accessed we can add 4-bytes (in 32-bit architecture) in ESP and it would move to value of x. Now what if we call a function inside another function/porgram? the stack would grow to accomodate new function and ESP would also move to the top of the stack, and when we return from the function we would no longer able to access the stack segments as we haven't saved current value of ESP anywhere. To solve this problem, we have another register EBP (Extended Base Pointer), this register keeps the copy of ESP or just points to a fixed location in stack. We have two registers now, ESP pointing to the top of the stack, it can move freely as needed, and EBP which is pointing to a fixed location and other segments can be accessed with the offset of EBP. In this case, when we call another function, we can push the value of EBP into the stack of new function, so that when the function finishes we get back our base pointer. The "Previous Frame Pointer" in above example is basically value of EBP from previous/callee function. 
- **Local Variables**: next local variables are pushed to stack, the order of the variable is up to the compiler


**A Vulnerable Program**
Now let's see how a vulnerable program looks like and what happens when buffer overflows. 

Following is a vulnerable program (taken from ([this book](http://www.cis.syr.edu/~wedu/seed/Book/book_sample_buffer.pdf))):

```
#include <string.h>
void foo(char *str)
{
char buffer[12];
/* The following statement will result in buffer overflow */
strcpy(buffer, str);
}
int main()
{
char *str = "This is definitely longer than 12";
foo(str);
return 1;
}
```

The stack arrangement would be:
![stack](https://github.com/azizahsan/Buffer-Overflow/blob/master/stack.png?raw=true)

The stack grows from higher to lower addresses but the buffer grows normally i.e. lower to higher. The function foo() takes an argumnets and directly copies it to the buffer using function strcpy(), the buffer is declared as 12-bytes long, but in above program the string is longer, so this string will overflow the buffer and overwrites other parts of stack, i.e. "Previous Frame Pointer", "Return Address" etc. As the return address is modified, the function would try to return to the new address and execute whatever is there, however if the new return address is out of the program allocated memory, the jump will fail and program will crash with a "segmentation fault" error. 

An adversary can take advantage of this scenario. If in a program like above, the string is actually a user input, an adversary can craft a string in such a way that he can control the return address, so that when the function returns, it actually returns on his injected code and executes it. Now how does an attacker inject code, and how does he know where is it on stack? most of the time he just enter input once which overflows the stack and jumps to his input; e.g. in above example attacker knows that buffer size is 12-bytes, the next 4-bytes are "Previous Frame Pointer" and then 4-bytes for "Return Address", so he can craft an input as follows:

```
"16bytes random string" + "A random address on the stack" + "malicious code"
```

The first 16-bytes would fill up the stack until the return address, then attacker's return address followed by malicious code. Attacker is hoping that the return address will be his address of his malicious code, if it doesn' work then he will try another address. Attacker can improve the probability of guessing the return address by adding some "no operation" bytes before the malicious code, it depends how much space is available on the stack, the payload would look like this: 

```
"16bytes random string" + "A random address on the stack" + "a lot of operations" + "malicious code"
```
Now attacker has to just jump one of the address on one of the no operatoin bytes and it will lead to his malicious code. 

Okay, I think enough of theory and hope you understand how the overflow works. We take a practical exmaple now. 

# Brainpan:1 Walkthrough

I am using a vulnerbale machine from vulnhub [Brainpan:1](https://www.vulnhub.com/entry/brainpan-1,51/)

I found it very good to practice buffer overflow. 

If you're using VirtualBox, just unzip the downloaded file and file->import appliance, it would take a couple of minutes to load. Then go settings of the VM and set network adapter as "Host-only". Boot up Brainpan and also the your attacking machine (I am using Kali with Host-only adapter). My attacking machine got IP:192.168.56.101, the brainpan should also get the IP in same subnet, so try to ping 102, 103 or use netdiscover to find out; for me brainpan got 192.168.56.102. 

An nmap scan would give us two open ports:

```
nmap -p- -A 192.168.56.102
Starting Nmap 7.70 ( https://nmap.org ) at 2019-02-20 17:22 AEDT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.102
Host is up (0.00046s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.70%I=7%D=2/20%Time=5C6CF250%P=i686-pc-linux-gnu%r(NULL
SF:,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|_\|\x
SF:20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x2
SF:0\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\|\x20
SF:\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20
SF:\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20
SF:\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20
SF:_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x20\x20
SF:\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20_\|
SF:\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x20\x20
SF:_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPAN\x20
SF:_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTER\x20
SF:THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20>>\x20");
MAC Address: 08:00:27:2A:0C:AE (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.10
Network Distance: 1 hop

TRACEROUTE
HOP RTT     ADDRESS
1   0.46 ms 192.168.56.102

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.92 seconds
```

Let's see what's at port 10000:
![website]()

Dirb on port 10000:

```
dirb http://192.168.56.102:10000

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Wed Feb 20 17:26:34 2019
URL_BASE: http://192.168.56.102:10000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://192.168.56.102:10000/ ----
+ http://192.168.56.102:10000/bin (CODE:301|SIZE:0)                                                                                  
+ http://192.168.56.102:10000/index.html (CODE:200|SIZE:215)                                                                         
                                                                                                                                     
-----------------
END_TIME: Wed Feb 20 17:26:48 2019
DOWNLOADED: 4612 - FOUND: 2
```

Let's see what's in the bin folder:
![bin]()

Port 9999 doesn't give anyting with browser, let's connect it with netcat:
![port]()

It asks for password which we don't have at this stage. 

Let's download the brainpan.exe from /bin/ on port 10000 and analyse it. 

```
file brainpan.exe
brainpan.exe: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
root@kali:~/Downloads# strings brainpan.exe
!This program cannot be run in DOS mode.
.text
`.data
.rdata
@.bss
.idata
[^_]
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
AAAA
[^_]
[get_reply] s = [%s]
[get_reply] copied %d bytes to buffer
shitstorm
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|
[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              
                          >> 
                          ACCESS DENIED
                          ACCESS GRANTED
[+] initializing winsock...
[!] winsock init failed: %d
done.
[!] could not create socket: %d
[+] server socket created.
[!] bind failed: %d
[+] bind done on port %d
[+] waiting for connections.
[+] received connection.
[+] check is %d
[!] accept failed: %d
[+] cleaning up.
-LIBGCCW32-EH-3-SJLJ-GTHR-MINGW32
w32_sharedptr->size == sizeof(W32_EH_SHARED)
../../gcc-3.4.5/gcc/config/i386/w32-shared-ptr.c
GetAtomNameA (atom, s, sizeof(s)) != 0
AddAtomA
ExitProcess
FindAtomA
GetAtomNameA
SetUnhandledExceptionFilter
__getmainargs
__p__environ
__p__fmode
__set_app_type
_assert
_cexit
_iob
_onexit
_setmode
abort
atexit
free
malloc
memset
printf
signal
strcmp
strcpy
strlen
WSACleanup
WSAGetLastError
WSAStartup
accept
bind
closesocket
htons
listen
recv
send
socket
```

So this is 32-bit windows binary and have functions like strcpy/strcmp and possible vulnerable to buffer overflow. I will run this binary on Windows 7 virtual machine (you can download it from [here](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)), I also have installed [immunity debugger](https://www.immunityinc.com/products/debugger/) with [mona scripts](https://github.com/corelan/mona). 

When I run brainpan.exe it opens port 9999 on my windows, and we can connect to it from our Kali. 

Let's run brainpan.exe and attack debugger to it (start immunity debugger and file->attach->brainpan.exe) and press start program button. We can see the state of registers and memory dump, we can right-click on any register and "follow-dump" to see where is it pointing to in the memory. 

![immunity]()

My windows machine got IP:192.168.56.103. We can use following python code to fuzz the application. This code will send input string (payload) to the application on port 9999. It will start with a single alphet input (A) and then start increasing the payload with the multiple of 100, i.e. first paylaod is "A", next payload is 100 A's and next would be 200 A's and so on. We can open the windows machine and see when the application crashes.

```
#!/usr/bin/python
import socket

buffer=["A"]
counter=100
while len(buffer) <= 20:
	buffer.append("A"*counter)
	counter=counter+100
for string in buffer:
    print "Fuzzing PASS with %s bytes" % len(string)
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connect=s.connect(('192.168.56.103',9999))
    s.recv(1024)	
s.send(string + '\r\n')
s.close()
```
So it sent 2000 bytes of data and our application crashed, we can see the error on our debugger. If we have a look on registers:

![registers]()

EIP (Extended Instruction Pointer) holds the address of the next instruction, it tells the computer where to go next to execute the next command and controls the flow of a program, or we can say EIP has the return address. So in our case after the crash EIP is overwritten, means we've modified the return address with our payload. Now we need to find out which part of our paylaod actually modified the EIP, to do that we can generate a unique string and send it to the application. A module from metasploit can be used to generate a unique string:

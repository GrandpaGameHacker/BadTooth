# BadTooth
Python Game Cheat Framework

# Development Goals
- Modular minimalistic design
- No Dependencies*
- Interactive shell script system
- Flexibility
- Scriptability

# Prototype Dev Goals
- Implement Windows API using ctypes
- Each seperate by DLL e.g. kernel32.py
- A Wrapper accesses dll directly, e.g. memory.py
- Windows constants stored in its own .py file


# About Not Having Dependencies
I'd prefer this library to be fully independent, however
some features like easy hooking (dont need to specify instruction sizes)
would need other libraries like capstone. I will create another
version of BadTooth in the future with these features, and make this one
'Badtooth Lite'
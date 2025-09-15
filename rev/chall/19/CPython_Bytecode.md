# **CPython Bytecode**

Python bytecode is a low-level, intermediate representation of your Python source code. When you run a Python script, the Python interpreter first compiles the source code into bytecode. This bytecode is then executed by the Python Virtual Machine (PVM). 

Here's a breakdown of its key aspects:

- Intermediate Representation
- Platform Independence
- Execution by the Python Virtual Machine (PVM)
- .pyc Files and __pycache__:


Disassembly:
The [dis](https://docs.python.org/3/library/dis.html) module in Python's standard library allows you to disassemble Python bytecode, providing a human-readable representation of the instructions and their parameters. This can be useful for understanding how Python code is executed at a lower level.


* Each instruction is:

  * An **opcode** (e.g., `LOAD_CONST`, `CALL`, `RETURN_VALUE`).
  * Sometimes followed by an **argument** (e.g., which constant to load).
* Instructions are executed by the **Python Virtual Machine (PVM)** stack machine.
* It is **stack-based**, meaning most operations push and pop values from the operand stack.

---

## 🔑 Common CPython Bytecode Instructions (with details)

### 1. Function & Control

* **`RESUME n`** → Marks function entry point (newer Python versions use it instead of `LOAD_CONST` for function start).
* **`RETURN_VALUE`** → Pops top of stack and returns it from the function.
* **`JUMP_ABSOLUTE target`** → Jump unconditionally to a bytecode offset.
* **`POP_JUMP_IF_FALSE target`** → Pops top of stack, jumps if false.
* **`POP_JUMP_IF_TRUE target`** → Pops top of stack, jumps if true.
* **`SETUP_FINALLY` / `SETUP_EXCEPT`** → Exception handling setup.

---

### 2. Data & Variables

* **`LOAD_CONST index`** → Push constant (from `co_consts`) onto stack.
* **`LOAD_FAST index`** → Pushes local variable onto stack.
* **`STORE_FAST index`** → Pops stack and stores into local variable.
* **`LOAD_GLOBAL index`** → Loads a global variable (e.g., `len`).
* **`STORE_GLOBAL index`** → Stores top of stack into global variable.
* **`LOAD_ATTR name`** → Gets an attribute from object (`obj.attr`).
* **`STORE_ATTR name`** → Sets attribute (`obj.attr = value`).

---

### 3. Stack Operations

* **`POP_TOP`** → Pops and discards top of stack.
* **`DUP_TOP`** → Duplicates top stack value.
* **`ROT_TWO` / `ROT_THREE`** → Rotates top stack values.

---

### 4. Function Calls

* **`CALL n`** → Calls a function with `n` arguments from stack.
* **`CALL_FUNCTION`** (older Python) → Similar to above.
* **`MAKE_FUNCTION`** → Creates a function object from code object.
* **`PRECALL`** (newer) → Prepares stack before actual `CALL`.

---

### 5. Arithmetic & Logic

* **`BINARY_ADD`** → Pops two items, pushes their sum.
* **`BINARY_SUBTRACT`**
* **`BINARY_MULTIPLY`**
* **`BINARY_TRUE_DIVIDE`**
* **`BINARY_AND` / `BINARY_OR` / `BINARY_XOR`**
* **`COMPARE_OP op`** → Compares two top stack values (e.g., `<`, `==`).

---

### 6. Iteration

* **`GET_ITER`** → Converts iterable into an iterator.
* **`FOR_ITER target`** → Gets next item or jumps if exhausted.

---

## Example

```python
def myfunc(alist):
    return len(alist)
```

Disassembled:

```
  3           RESUME                   0
  4           LOAD_GLOBAL              1 (len + NULL)
              LOAD_FAST                0 (alist)
              CALL                     1
              RETURN_VALUE
```

Step-by-step:

1. `RESUME 0` → Marks function entry.
2. `LOAD_GLOBAL len` → Pushes built-in function `len` on stack.
3. `LOAD_FAST alist` → Pushes the function argument (`alist`) on stack.
4. `CALL 1` → Calls `len` with 1 argument (`alist`).
5. `RETURN_VALUE` → Returns result of `len`.

---



to see more instructions with their opcode click [here](https://unpyc.sourceforge.net/Opcodes.html)

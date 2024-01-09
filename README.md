# sword 🗡️
> SomeWhat Of a Recursive Disassembler

Attempting to recreate the output of `objdump`

```
objdump -d -M intel test
```

However, `objdump` follows a linear sweep patteren in which it may not always produce the correct results in differentiating between data and code. Recursive disassembly is the solution to this and attempts to improve upon a linear sweep.
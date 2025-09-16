# **unpackme**

## Description

> Can you get the flag? Reverse engineer this binary.

Let's first see if it is packed or not.

![file](./img/file.png)

It is packed using [UPX](https://github.com/upx/upx.git).

We can also see this by using [DIE (Detect-It-Easy)](https://github.com/horsicq/Detect-It-Easy.git).

![die](./img/die.png)

Let's unpack it using UPX.

![upx\_d](./img/upx_d.png)

When we run the binary it asks for our favourite colour — or, let's say, it's 😒

![first](./img/first.png)

Let's open it in IDA and see what its favourite colour is.

![ida](./img/ida.png)

Hmm — its favourite colour is `754635`. What colour is this? 😒

![flag](./img/flag.png)

# **packer**

Description:

> Reverse this linux executable?

![file](./img/file.png)

if we open it using IDA

![ida](./img/ida_packed.png)

we can see that there are very less functions

lets cheak for if it is packed or not 


![upx](./img/upx.png)


UPX packers leave markers like UPX!, UPX0, UPX1 in the binary. Seeing that is a reliable indicator the file was packed with UPX (not just stripped).


![upx_t](./img/upx_t.png)

“OK” from upx -t means UPX thinks the packed file is valid and recoverable.

lets unpack the binary

![upx_d](./img/upx_d.png)

now it is unpacked lets open it in IDA


![ida_fix](./img/ida_fix.png)


here we can see the string `7069636f4354467b5539585f556e5034636b314e365f42316e34526933535f62646438343839337d` now lets use [CyberChef](https://gchq.github.io/CyberChef/) magic to get the flag

![result](./img/result.png)
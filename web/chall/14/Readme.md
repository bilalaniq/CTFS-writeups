# Cookies

## Description

> Who doesn't love cookies? Try to figure out the best one. http://mercury.picoctf.net:6418/


![first](./img/first.png)

lets look for cookies 🍪

![-1](./img/cookie_firs.png)

here we can see that the cookie value is `-1` at the start

lets enter `snickerdoodle` 

![hint](./img/i_love.png)

now lets look into the cookies value 

![zero](./img/zero.png)

lets open burpsuit

![burp](./img/burp.png)

we will now bruteforce the value for which we will get flag

send the request to the intruder

![intruder](./img/intruder.png)

![variable](./img/variable.png)

now we can see 

```bash
Cookie: name=§0§
```

we are going to create an payload that makes request with this value changed

so if we are lucky we can get the right value 

![payload](./img/payload.png)

this is the payload config that i am using

it will go from `1-20` and get the flag

click `start attack` and see the magic for your self

go through all the response for me it was at the `18`

![result](./img/result.png)
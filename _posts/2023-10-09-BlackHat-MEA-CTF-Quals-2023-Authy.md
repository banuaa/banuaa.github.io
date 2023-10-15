---
title:  "BlackHat MEA CTF Quals 2023 - Authy [Web]"
date:   2023-10-09 00:00:00
categories: [Web]
tags: [Web]
---
Last week, i participated in BlackHat MEA CTF Qualification 2023 with the pty.spawn team and managed to solve several challenges. One of the challenges that I solved was the Authy (Web). My team qualified for the finals in Riyadh, but sadly, we couldn't go because we didn't have enough money for accommodation and other stuff. They only funded the top 10 teams. :(

<!--more-->

**Challenge Description:**\
`I have just learned Golang and trying to build a small authentication platform with it. It's a simple API so it should be secure right ?`\
`Author: SAFCSP`

**Attachment:**\
[Authy.zip](/files/Authy.zip)

**Analysis:**\
After conducting a brief analysis of several files, the application flow is as follows:
1. File Server.go: There are two endpoints, namely "/login" and "/registration," with the POST method.
2. File Models.go: The Users data model consists of Username, Firstname, Lastname, Password, Token, and DateCreated.
3. File LoginController.go: There are two functions for login and registration. The registration function receives POST requests in JSON format containing Username, Firstname, Lastname, and Password. The login function is similar to registration but receives POST requests in JSON format with only Username and Password.
4. File LoginController.go: The flag is obtained after login, with the condition that the password length of the logging-in user must be less than 6 characters.

**Vulnerable Code**
``` go
    ......SNIP......
    var user models.Users

    if len(user.Password) < 6 {
    log.Error("Password too short")
    resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "Password too short", "EXT_REF"))
    return resp
    }

    ......SNIP......

	password := []rune(user.Password)
	result.Token = helper.JwtGenerator(result.Username, result.Firstname, result.Lastname, os.Getenv("SECRET"))
	if len(password) < 6 {
		flag := os.Getenv("FLAG")
		res := &Flag{
			Flag: flag,
		}
		resp := c.JSON(http.StatusOK, res)
		log.Info()
		return resp
	}
    ......SNIP......
```
The flag is obtained after successfully creating a user with a password length of less than 6 characters. However, during registration, there is a password length validation. Because the login process uses []rune, where []rune reads non-ASCII characters as they are, without being directly read as bytes or escaped, we can bypass the registration by entering non-ASCII characters as the password.

Here is an example of debugging the []rune:
``` go
package main
import "fmt"

func main() {
    latin := "ééé"
    fmt.Println(len(latin))
    fmt.Println(len([]rune(latin)))
}
```
![Debugging](/images/post/BlackHat-MEA-CTF-Quals-2023_Authy1.png)

1. The Latin "é" requires 2 bytes in UTF-8, so if you call len("é"), the output will be 2 characters.
2. Register with these Latin characters three times, and the login process will read it as 6 characters.
3. Logging in with the password "ééé," []rune will read it as Latin characters (non-UTF-8), so its length will be less than 6 characters, and you will obtain the flag.

Run the payload, and the flag is obtained! I ran it locally because I can't start an instance again after submitting the flag.
![Flag](/images/post/BlackHat-MEA-CTF-Quals-2023_Authy2.png)

**Real Flag**: BHFlagY{f6666525f4fa1f0e32c7dc9c8d987d82}

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn

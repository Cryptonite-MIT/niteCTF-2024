# Solution

We need to perform a HMAC-Based **Hash Length Extension Attack** to authenticate as "Bob" and gain access to the vault code. We'll use [hashpump](https://github.com/miekrr/HashPump) tool to perform the attack.

The secret key is unknown to you, but since MD5 is a Merkle–Damgård hash function, it's vulnerable to length extension attacks. Hash length extension attacks allow you to add data to the end of an already hashed message without knowing the original secret.

## Analysis

The script shows that the length of the secret key is 21

So, it md5 hashes the `secret+msg`

- The key is of 21 bytes.
- The script shows us that we get the vault code if the message that we sent to Alice contains the word **`Bob`** and the hash for that message is verified.

## The Attack

- Go to practice convo and encrypt a message. For example - `SOMETHING`. We get the b64 encoded hash of the message.
- Decode the b64 hash and perform Hash Length Extension Attack using hashpump.
- The syntax to perform the attack is

   `hashpump -s <md5_hash_of_a_known_message> -d <"known_message"> -a <"message_to_append"> -k <key_length>`

- The script checks if the message we sent has the string **`Bob`** in it. So we append Bob to the known hash and sign it again.
- To perform the attack, we do. This will give us the new signature.

   `hashpump -s <md5_hash_of_SOMETHING> -d <"SOMETHING"> -a <"Bob"> -k <21>`

- Now we select `Let's Fool Alice!` option from the menu. We input **`Bob`** when it asks for your name and provide the new signature as input for HMAC.


This will give us the vault code and we can input this in `Crack the Vault` choice to get the flag


**Or if you're smart, there's an easy way out lmao**


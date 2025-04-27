Explanation of the encryption/decryption flow and a comparison between AES and RSA in terms of speed, use case, and security.

Python code provides hybrid encryption process, when Alice sends secret message to Bob implementing AES-256 symmetric encryption for efficiency and RSA key pair to securly exchange symmetric key. 
AES encryption is fast, used for encryption and decryption, reliable, effective to use for large data, key sizes are relatively smaller, but if leaked, compromises all data and communications. 
RSA encryption is slower, use larger kays as public and private, computationally more exostive, is vulnerable for padding oracle attacks if misused. 
In hybrid encryption model, when  AES and RSA encryption is combined, process is more secure, effective, allows to ensure confidentiality and integrity. 
      
Process takes several steps. 
Step 1. Bob generates an RSA 2048-bit key pair, which are saved as Bob's RSA private key and public key: private.pem; public.pem 
Step 2. Alice creates plaintext message as: alice_message.txt.
Step 3. Alice implements several substeps:
-	generates 256-bit AES key and IV.
-	message using AES-256 (in CBC mode) and padding PKCS#7.
-	stores received ciphertext as - encrypted_file.bin.
-	encrypts AES key using Bob’s public RSA key and receives - aes_key_encrypted.bin.
Step 4. Bob’s actions for decryption: 
-	decrypts AES key using his RSA private key.
-	extracts the IV from encrypted_file.bin and decrypts ciphertext using previously decrypted AES key.
-	saves plaintext received in result as - decrypted_message.txt.
Step 5. Bob verifies integrity of files
-	Bob calculates and compares SHA-256 hash of alice_message.txt and decrypted_message.txt.
-	Since results match each other, it confirms message integrity.
Output Files
-	public.pem
-	private.pem  
-	alice_message.txt  
-	encrypted_file.bin  
-	aes_key_encrypted.bin  
-	decrypted_message.txt  

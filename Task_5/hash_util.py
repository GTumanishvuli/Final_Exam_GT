#!/usr/bin/env python
# coding: utf-8

# In[1]:


# Step 1: Define hashing function
def compute_hashes(file_path):
    hashes = {
        'SHA-256': None,
        'SHA-1': None,
        'MD5': None
    }
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            hashes['SHA-256'] = hashlib.sha256(data).hexdigest()
            hashes['SHA-1'] = hashlib.sha1(data).hexdigest()
            hashes['MD5'] = hashlib.md5(data).hexdigest()
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        sys.exit(1)

    return hashes


# In[3]:


# Step 2: Save hashes to a JSON file
def save_hashes(hashes, filename):
    with open(filename, 'w') as f:
        json.dump(hashes, f, indent=4)


# In[5]:


# Step 3: Load hashes from a JSON file
def load_hashes(filename):
    with open(filename, 'r') as f:
        return json.load(f)


# In[7]:


# Step 4: Integrity check
def check_integrity(original_hashes, new_hashes):
    integrity_ok = True
    for algo in original_hashes:
        if original_hashes[algo] != new_hashes[algo]:
            print(f"[WARNING] {algo} hash mismatch!")
            integrity_ok = False
    if integrity_ok:
        print("[PASS] Integrity check passed.")
    else:
        print("[FAIL] Integrity check failed.")

if __name__ == "__main__":
    # Create original.txt
    with open("original.txt", "w") as f:
        f.write("This is original file to test 1.\n")

    print("Computing hashes for original.txt...")
    original_hashes = compute_hashes("original.txt")
    save_hashes(original_hashes, "hashes.json")


# In[13]:


# Simulate tampering
with open("tampered.txt", "w") as f:
    f.write("This file was tampered 1.\n")

print("Computing hashes for tampered.txt...")
tampered_hashes = compute_hashes("tampered.txt")


# In[15]:


# Load original hashes
saved_hashes = load_hashes("hashes.json")


# In[17]:


# Compare and detect tampering
print("Checking file integrity...")
check_integrity(saved_hashes, tampered_hashes)


# In[ ]:





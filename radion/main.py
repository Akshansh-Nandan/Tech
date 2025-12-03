import time
import random
import radion

def hash_data(data:str):
    print("Generating Hash...")
    print()

    time1 = time.time()
    rhash = radion.hash_data(data)
    time2 = time.time()

    l = 200

    print(f"Data: { data[:l] + ('...' if len(data) > l else '') }")
    print(f"Hash: { rhash }")
    print()
    print(f"Completed in { time2 - time1 }s")

    return rhash

hash_data("Data : Top Secret - National States") # Mini warmup test
hash_data("".join([random.choice([i for i in "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?"]) for _ in range(1024 ** 2)])) # Test
hash_data("".join([random.choice([i for i in "1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?"]) for _ in range(1024 ** 3)])) # Exam



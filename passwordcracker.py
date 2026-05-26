import hashlib
import itertools
import string
import argparse
import threading
import time
from queue import Queue, Full


found_password = None
attempt_count  = 0
stop_event     = threading.Event()

CHARSETS = {
    "alpha":    string.ascii_lowercase,
    "alphanum": string.ascii_lowercase + string.digits,
    "digits":   string.digits,
    "full":     string.ascii_letters + string.digits + string.punctuation,
}


def worker(queue: Queue, target_hash: str, algorithm: str):
    global found_password, attempt_count
    while True:
        candidate = queue.get()
        if candidate is None:
            queue.task_done()
            break
        attempt_count += 1
        if hashlib.new(algorithm, candidate.encode()).hexdigest() == target_hash:
            found_password = candidate
            stop_event.set()
        queue.task_done()
        if stop_event.is_set():
            break

def _launch(target_hash, algorithm, num_threads):
    queue = Queue(maxsize=num_threads * 200)
    threads = [threading.Thread(target=worker, args=(queue, target_hash, algorithm), daemon=True)
               for _ in range(num_threads)]
    for t in threads: t.start()
    return queue, threads

def _shutdown(queue, threads, num_threads):
    for _ in range(num_threads):
        try:
            queue.put(None, block=False)
        except Full:
            pass
    for t in threads:
        t.join(timeout=2)

def dictionary_attack(target_hash, algorithm, wordlist_path, num_threads):
    print(f"[*] Dictionary attack | wordlist: {wordlist_path} | threads: {num_threads}")
    queue, threads = _launch(target_hash, algorithm, num_threads)
    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                if stop_event.is_set(): break
                word = line.strip()
                if word:
                    try:
                        queue.put(word, timeout=1)
                    except Full:
                        pass
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {wordlist_path}")
        stop_event.set()
    _shutdown(queue, threads, num_threads)

def brute_force_attack(target_hash, algorithm, min_len, max_len, charset, num_threads):
    print(f"[*] Brute-force attack | length: {min_len}-{max_len} | charset: {len(charset)} chars | threads: {num_threads}")
    queue, threads = _launch(target_hash, algorithm, num_threads)
    for length in range(min_len, max_len + 1):
        if stop_event.is_set(): break
        for combo in itertools.product(charset, repeat=length):
            if stop_event.is_set(): break
            try:
                queue.put("".join(combo), timeout=1)
            except Full:
                pass
    _shutdown(queue, threads, num_threads)

def main():
    parser = argparse.ArgumentParser(description="Password Cracker — Inlighn Tech")
    parser.add_argument("hash", nargs="?", default="5d41402abc4b2a76b9719d911017c592", help="Target hash to crack")
    parser.add_argument("-a", "--algorithm",  default="md5",
                        choices=["md5","sha1","sha224","sha256","sha384","sha512"],
                        help="Hash algorithm (default: md5)")
    parser.add_argument("-w", "--wordlist",   help="Path to wordlist file")
    parser.add_argument("--min-len", type=int, default=1, help="Min brute-force length (default: 1)")
    parser.add_argument("--max-len", type=int, default=5, help="Max brute-force length (default: 5)")
    parser.add_argument("--charset", default="alpha",
                        help="alpha | alphanum | digits | full | custom string")
    parser.add_argument("-t", "--threads", type=int, default=4, help="Thread count (default: 4)")
    args = parser.parse_args()

    charset = CHARSETS.get(args.charset, args.charset)
    print(f"\n[*] Target    : {args.hash}")
    print(f"[*] Algorithm : {args.algorithm.upper()}\n")

    start = time.time()

    if args.wordlist:
        dictionary_attack(args.hash, args.algorithm, args.wordlist, args.threads)
        if not found_password:
            print("[*] Wordlist exhausted. Falling back to brute-force...")
            stop_event.clear()
            brute_force_attack(args.hash, args.algorithm, args.min_len, args.max_len, charset, args.threads)
    else:
        brute_force_attack(args.hash, args.algorithm, args.min_len, args.max_len, charset, args.threads)

    elapsed = time.time() - start
    print(f"\n{'='*45}")
    print(f"  [+] CRACKED : {found_password}" if found_password else "  [-] Password not found.")
    print(f"  [i] Attempts: {attempt_count:,}")
    print(f"  [i] Time    : {elapsed:.2f}s")
    print('='*45)

if __name__ == "__main__":
    main()
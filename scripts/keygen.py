import os
from shared.crypto_utils import generate_keypair, get_public_key_fingerprint

def run_keygen():
    keys_dir = "keys"
    if not os.path.exists(keys_dir):
        os.makedirs(keys_dir)
        print(f"Created directory: {keys_dir}")

    private_key_path = os.path.join(keys_dir, "private_key.pem")
    public_key_path = os.path.join(keys_dir, "public_key.pem")

    if os.path.exists(private_key_path):
        confirm = input("Keys already exist. Overwrite? (y/n): ")
        if confirm.lower() != 'y':
            print("Aborting.")
            return

    # Generate keys
    private_pem, public_pem = generate_keypair()

    # Save to disk
    with open(private_key_path, "wb") as f:
        f.write(private_pem)
    with open(public_key_path, "wb") as f:
        f.write(public_pem)

    fingerprint = get_public_key_fingerprint(public_pem)
    print(f"✓ Keys generated successfully.")
    print(f"✓ Public Key Fingerprint: {fingerprint}")
    print(f"✓ Private key saved to: {private_key_path}")

if __name__ == "__main__":
    run_keygen()
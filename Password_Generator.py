import secrets
import string

class PasswordPolicy:
    """Defines the rules for generating a password for a specific platform."""
    def __init__(self, length, use_upper=True, use_lower=True, use_digits=True, use_symbols=True, safe_symbols_only=False):
        self.length = length
        self.use_upper = use_upper
        self.use_lower = use_lower
        self.use_digits = use_digits
        self.use_symbols = use_symbols
        self.symbols = "!@#$%^&*" if safe_symbols_only else string.punctuation

class PasswordGenerator:
    """Generates passwords based on platform-specific policies."""

    def __init__(self):
        self.policies = {
            "social": PasswordPolicy(length=16),
            "banking": PasswordPolicy(length=12, safe_symbols_only=True),
            "pin": PasswordPolicy(length=6, use_upper=False, use_lower=False, use_symbols=False),
            "corporate": PasswordPolicy(length=24),
            "wifi": PasswordPolicy(length=20, use_symbols=False)
        }

    def generate(self, platform_type="social") -> str:
        """Generates a secure password based on the requested platform."""
        policy = self.policies[platform_type]

        pool = ""
        password_chars = []

        # Ensure at least one of each required character type
        if policy.use_upper:
            pool += string.ascii_uppercase
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if policy.use_lower:
            pool += string.ascii_lowercase
            password_chars.append(secrets.choice(string.ascii_lowercase))
        if policy.use_digits:
            pool += string.digits
            password_chars.append(secrets.choice(string.digits))
        if policy.use_symbols:
            pool += policy.symbols
            password_chars.append(secrets.choice(policy.symbols))

        # Fill the remaining length
        remaining_length = policy.length - len(password_chars)
        for _ in range(remaining_length):
            password_chars.append(secrets.choice(pool))

        # Shuffle the result
        secure_random = secrets.SystemRandom()
        secure_random.shuffle(password_chars)

        return "".join(password_chars)

# --- Interactive Command Line Interface ---
if __name__ == "__main__":
    generator = PasswordGenerator()
    available_platforms = list(generator.policies.keys())

    print("========================================")
    print("  Platform-Aware Password Generator")
    print("========================================")

    while True:
        # 1. Display the menu dynamically based on available policies
        print("\nAvailable platforms:")
        for idx, platform in enumerate(available_platforms, 1):
            print(f"  {idx}. {platform.capitalize()}")
        print("  0. Exit")

        # 2. Ask the user for input
        choice = input("\nEnter the name or number of the platform (or 0 to exit): ").strip().lower()

        # 3. Handle exit condition
        if choice == '0' or choice == 'exit':
            print("Exiting generator. Stay secure!")
            break

        # 4. Process the user's choice (allowing both number and string inputs)
        selected_platform = None

        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(available_platforms):
                selected_platform = available_platforms[idx - 1]
        elif choice in available_platforms:
            selected_platform = choice

        # 5. Generate or show error
        if selected_platform:
            pwd = generator.generate(selected_platform)
            print("-" * 40)
            print(f"[{selected_platform.upper()}] Password generated:")
            print(f"-->  {pwd}  <--")
            print("-" * 40)
        else:
            print(f"Error: Invalid selection '{choice}'. Please try again.")

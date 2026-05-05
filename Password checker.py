import random
import string

# ============================================================
#   PASSWORD STRENGTH CHECKER + GENERATOR
#   Project by: [Your Name]
#   Concepts: Security rules, Hashing, Password policies
# ============================================================


def check_strength(password):
    """
    Checks the strength of a given password.
    Returns a score and feedback.
    """
    score = 0
    feedback = []

    # Rule 1: Length check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long.")

    if len(password) >= 12:
        score += 1
    else:
        feedback.append("💡 Tip: Using 12+ characters makes it much stronger.")

    # Rule 2: Uppercase letter check
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("❌ Add at least one UPPERCASE letter (A-Z).")

    # Rule 3: Lowercase letter check
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("❌ Add at least one lowercase letter (a-z).")

    # Rule 4: Digit check
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("❌ Add at least one number (0-9).")

    # Rule 5: Special character check
    special_chars = "!@#$%^&*()_+-=[]{}|;:',.<>?/"
    if any(c in special_chars for c in password):
        score += 1
    else:
        feedback.append("❌ Add at least one special character (!@#$%^&* etc.).")

    # Rule 6: No common passwords check
    common_passwords = ["password", "123456", "password123", "admin", "qwerty", "abc123", "letmein"]
    if password.lower() in common_passwords:
        score = 0
        feedback.append("🚨 This is a very common password! Never use this.")

    # Determine strength level
    if score <= 2:
        strength = "🔴 WEAK"
    elif score <= 4:
        strength = "🟡 MODERATE"
    elif score == 5:
        strength = "🟠 STRONG"
    else:
        strength = "🟢 VERY STRONG"

    return score, strength, feedback


def generate_password(length=12, use_upper=True, use_digits=True, use_special=True):
    """
    Generates a strong random password based on selected options.
    """
    characters = string.ascii_lowercase  # always include lowercase

    if use_upper:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += "!@#$%^&*()_+-="

    # Make sure at least one of each selected type is included
    password = []
    password.append(random.choice(string.ascii_lowercase))
    if use_upper:
        password.append(random.choice(string.ascii_uppercase))
    if use_digits:
        password.append(random.choice(string.digits))
    if use_special:
        password.append(random.choice("!@#$%^&*()_+-="))

    # Fill the rest randomly
    while len(password) < length:
        password.append(random.choice(characters))

    # Shuffle so the forced characters aren't always at the start
    random.shuffle(password)

    return ''.join(password)


def display_strength_bar(score):
    """
    Displays a visual strength bar in the terminal.
    """
    max_score = 6
    filled = int((score / max_score) * 20)
    bar = "█" * filled + "░" * (20 - filled)
    print(f"  Strength : [{bar}] {score}/{max_score}")


def main():
    print("=" * 50)
    print("   🔐 PASSWORD STRENGTH CHECKER + GENERATOR")
    print("=" * 50)

    while True:
        print("\nWhat would you like to do?")
        print("  1. Check password strength")
        print("  2. Generate a strong password")
        print("  3. Exit")

        choice = input("\nEnter your choice (1/2/3): ").strip()

        # ---- Option 1: Check Strength ----
        if choice == "1":
            print("\n--- PASSWORD STRENGTH CHECKER ---")
            password = input("Enter the password to check: ")

            score, strength, feedback = check_strength(password)

            print(f"\n  Result   : {strength}")
            display_strength_bar(score)

            if feedback:
                print("\n  Feedback:")
                for tip in feedback:
                    print(f"    {tip}")
            else:
                print("\n  ✅ Excellent! Your password meets all security rules.")

        # ---- Option 2: Generate Password ----
        elif choice == "2":
            print("\n--- PASSWORD GENERATOR ---")

            try:
                length = int(input("Enter desired password length (min 8, recommended 12-16): "))
                if length < 8:
                    print("  ⚠️  Minimum length is 8. Setting to 8.")
                    length = 8
            except ValueError:
                print("  ⚠️  Invalid input. Using default length of 12.")
                length = 12

            use_upper   = input("Include UPPERCASE letters? (y/n): ").lower() == 'y'
            use_digits  = input("Include numbers (0-9)? (y/n): ").lower() == 'y'
            use_special = input("Include special characters (!@#$...)? (y/n): ").lower() == 'y'

            generated = generate_password(length, use_upper, use_digits, use_special)
            score, strength, _ = check_strength(generated)

            print(f"\n  ✅ Generated Password : {generated}")
            print(f"  Strength             : {strength}")
            display_strength_bar(score)

        # ---- Option 3: Exit ----
        elif choice == "3":
            print("\n👋 Goodbye! Stay secure online.\n")
            break

        else:
            print("  ⚠️  Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
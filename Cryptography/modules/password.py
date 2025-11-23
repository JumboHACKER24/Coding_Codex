from zxcvbn import zxcvbn
from getpass import getpass
import bcrypt

def check_password_strength(password):
    """
    Check the strength of a password using zxcvbn library.
    
    Args:
        password (str): The password to be evaluated.
        
    Returns:
        dict: A dictionary containing the strength score and feedback.
    """
    result = zxcvbn(password)
    score = result['score']
    if score == 3:
        response = "Strong enough password: Score 3/4"
    elif score == 4:
        response = "Very strong password: Score 4/4"
    else:
        feedback = result.get('feedback')
        warning = feedback.get('warning')
        suggestions = feedback.get('suggestions')
        response = f"Weak password: Score of {score}/4. Warning: {warning}. Suggestions: {' '.join(suggestions)}"
    return response

def hash_password(password):
    """
    Hash a password using bcrypt.
    
    Args:
        password (str): The password to be hashed.
        
    Returns:
        str: The hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode('utf-8')

def verify_password(password_attempt, hashed):
    """
    Verify a password against a given bcrypt hash.
    
    Args:
        password_attempt (str): The password to verify.
        hashed (str): The bcrypt hashed password.
        
    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    if bcrypt.checkpw(password_attempt.encode(), hashed.encode()):
        return "Password is correct. Access granted."
    else:
        return "Password is incorrect. Access denied."

if __name__ == "__main__":
    while True:
        password = getpass("Enter a password to check its strength: ")
        print(check_password_strength(password))
        if check_password_strength(password).startswith("Weak password"):
            print("Please try again with a stronger password.\n")
        else:
            break
    
    hashed_password = hash_password(password)
    print(f"Hashed Password: {hashed_password}")
    attempt = getpass("Re-enter your password for verification: ")
    print(verify_password(attempt, hashed_password))
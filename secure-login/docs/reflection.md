Defensive Coding Reflection

Defensive input validation protects fintech applications by rejecting bad data at the system boundary, before it reaches the database or business logic. In our login system, validate_input blocks blank fields and usernames with unexpected characters (such as the quote in ' OR '1'='1), and every query is parameterized, so any remaining input is treated as data and never as SQL. This prevents injection attacks from bypassing authentication or exposing account data. Salted PBKDF2 hashing protects stored passwords, lockout after three failed attempts limits brute-force guessing, and generic error messages prevent attackers from learning which usernames exist or how the system works. Together, these layers reduce the risk of unauthorized access to customer accounts.



# Unicode Normalization Vulnerability: A Detailed Breakdown
(mostly cribbed from [https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/))

## 1. What is Unicode Normalization?

Unicode normalization is a process of converting a string of Unicode characters into a standardized form. This is necessary because Unicode allows multiple ways to represent the same character or sequence of characters.

## 2. The Vulnerability

The vulnerability occurs when an application performs Unicode normalization after security checks or input validation, potentially allowing an attacker to bypass these security measures.

## 3. How it works

1. **Input**: An attacker inputs a special Unicode character that looks visually similar to a normal character but has a different Unicode code point.
2. **Security Check**: The application's security checks (like input validation or WAF rules) don't recognize this special character as malicious.
3. **Normalization**: After the security checks, the application normalizes the Unicode, converting the special character to its standard form.
4. **Result**: The normalized character might now be something that would have been caught by the security checks if it was input directly.

## 4. Example with Special K (℮)

- Normal 'K': U+004B (LATIN CAPITAL LETTER K)
- Special 'K': U+212A (KELVIN SIGN)

When normalized, U+212A becomes U+004B, but it might bypass security checks before normalization.

## 5. Why it's dangerous

- Can bypass input validation
- Potential for XSS attacks
- Possible SQL injection if used in database queries
- Might allow unauthorized access or privilege escalation

## 6. Real-world scenario

Imagine a web application that blocks the word "ADMIN" in usernames:

- An attacker tries: "ADMIN" -> Blocked
- Attacker uses: "ADMIN" with the 'A' as U+0100 (Ā) -> Passes initial check
- After normalization: "ADMIN" -> Now the attacker has an "ADMIN" username

## 7. How our tool detects it

- We send a request with the Special K (℮) character
- We check if the response contains "SpecialK" (normalized) but not "Special℮" (original)
- If true, it means the application normalized our input after processing it

## 8. Mitigation

- Always normalize Unicode input before performing security checks or storing in a database
- Use libraries that handle Unicode securely
- Implement strong input validation that considers Unicode equivalence

## 9. Why it's hard to detect

- The vulnerability isn't always apparent from just looking at the code
- It requires understanding of how the application processes Unicode at different stages
- Different programming languages and frameworks handle Unicode differently

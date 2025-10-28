# KagePass - A1SBERG

KagePass is a high-entropy password generator built with Flask. It provides advanced password generation, password strength analysis, and integration with the "Have I Been Pwned?" (HIBP) database.

## Features

### Password Generation
- **Modes of Generation**
  - Count-based generation: specify numbers, lowercase, uppercase, and special characters.
  - Regex-based generation: create passwords matching a specific pattern.
  - Leet-speak conversion: transform custom strings using predefined mappings.
- **Advanced Controls**
  - Prefix and suffix support.
  - Total length enforcement.
  - Character exclusion lists.
  - Seed support for reproducible results.
- **Security**
  - Uses Python's `secrets` module for cryptographically secure random generation.

### Password Analysis
- **Strength Evaluation**: heuristic score (0–100) based on length and character diversity.
- **Entropy Calculation**: Shannon entropy estimation for security assessment.
- **Breach Checking**: Integration with HIBP API using k-anonymity (first 5 characters of SHA-1 hash).

### User Experience
- Responsive, modern cyber-themed interface.
- ARIA labels and full keyboard navigation support.
- No password storage; all processing is client-side (HIBP queries use secure API).

## Quick Start

### Prerequisites
- Python 3.7+
- Flask
- Python packages: `rstr`, `requests`

### Installation

1. Clone the project:

```bash
git clone https://github.com/kUrOSH1R0oo/KagePass
```

2. Install dependencies:

```bash
pip install flask rstr requests
```

3. Run the application:

```bash
python app.py
```

4. Open your browser at `http://localhost:5000`

## Project Structure

```bash
kagepass/
├── app.py                 # Flask backend
├── templates/
│   └── index.html         # Main HTML template
├── static/
│   ├── script.js          # Frontend JavaScript
│   ├── styles.css         # Styling and animations
│   └── a1sberg_logo.png   # Logo
```

## API Endpoints

### POST /generate
Generate passwords.

**Request JSON**:

```json
{
  "numbers": 2,
  "lowercase": 4,
  "uppercase": 2,
  "special_chars": 1,
  "amount": 5,
  "regex": "",
  "prefix": "pre_",
  "suffix": "_suf",
  "total_length": 0,
  "custom": "",
  "seed": 12345,
  "exclude_chars": "oO0",
  "output_format": "txt"
}
```

**Response JSON**:

{
  "passwords": [
    {
      "password": "pre_Ab3$d_suf",
      "strength": 80,
      "entropy": 45.2
    }
  ]
}

### POST /check_pwned
Check password breaches.

**Request JSON**:

{
  "password": "password123"
}

**Response JSON**:

{
  "status": "Found",
  "sha1": "cbfdac6008f9cab4083784cbd1874f76618d2a97",
  "breach_count": "12453",
  "message": "Identified in data breaches. Change this password immediately.",
  "color": "red"
}

### POST /download
Download generated passwords in TXT or JSON format.

## Usage Guide

### Basic Password Generation
1. Select the "Generate Passwords" tab.
2. Specify the number of each character type.
3. Set the number of passwords to generate.
4. Click "Generate".

### Advanced Features
- Regex Pattern Generation: Enter a regex pattern (requires `rstr`).
- Leet-Speak Conversion: Enter a custom string; the generator converts it.
- Prefix/Suffix: Add fixed strings to the start/end of passwords.
- Character Exclusion: Exclude specific characters (e.g., `l1IO0`).
- Seed for Reproducibility: Generates the same passwords repeatedly for testing.

### Password Security Checking
1. Select the "Check Pwned" tab.
2. Enter a password.
3. Click "Check" to verify against the HIBP database.
4. View breach status and recommendations.

## Security Features
- Cryptographic randomness using `secrets.SystemRandom()`.
- Client-side processing; passwords are never stored.
- Secure API integration with HIBP using k-anonymity.
- Comprehensive input validation.

## UI/UX Features
- Cyber-themed design with glow effects.
- Responsive layout for desktop and mobile.
- Loading indicators during generation and checking.
- One-click password copy.
- Export options: TXT or JSON.
- Password strength visualization.
- Full accessibility support.

## Configuration

### Character Pools
- Digits: 0-9
- Lowercase: a-z
- Uppercase: A-Z
- Special: !@#$%^&*(),.?":{}|<>

### Leet-Speak Mapping
- a → 4, e → 3, i → !, o → 0, s → $, etc.

## Troubleshooting

- "No available characters after applying exclusions": Adjust character counts or exclusions.
- "Total length is less than required": Increase total length or reduce prefix/suffix.
- Regex generation fails: Ensure `rstr` is installed.
- HIBP check times out: Verify internet connection; endpoint may be temporarily unavailable.

### Debug Mode
Enable Flask debug mode in `app.py`:

if __name__ == '__main__':
    app.run(debug=True)

## License
Owned and maintained by A1SBERG Cybersecurity Organization of PUPSMB.

## Contributing
Built by kur0sh1ro for A1SBERG. Contact the organization for contributions.

## Technical Details

### Password Strength Algorithm
- Score (0-100) based on length and character diversity.
- Bonus points for extended length.

### Entropy Calculation
- Shannon entropy based on character set:
  - Digits: 10
  - Lowercase: 26
  - Uppercase: 26
  - Special: ~32

### HIBP Integration
- Uses k-anonymity (first 5 characters of SHA-1 hash sent).
- Secure HTTPS communication.
- Handles network timeouts.

---

**Note:** Always use generated passwords responsibly. Ensure compliance with security policies, update passwords regularly, and enable multi-factor authentication where available.



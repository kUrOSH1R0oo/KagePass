# app.py
# Author: Fredmark Ivan "Kur0Sh1r0" Dizon

from flask import Flask, render_template, request, jsonify, send_file
import io
import random
import string
import json
import secrets
import re
import math
import requests
import hashlib

app = Flask(__name__)

# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def leet_speak_conversion(custom_string):
    """Convert a string to leet-speak using a static mapping."""
    leet_mapping = {
        'a': '4', 'b': '8', 'c': '<', 'd': '|)', 'e': '3', 'f': '|=', 'g': '9',
        'h': '#', 'i': '!', 'j': '_|', 'k': '|<', 'l': '1', 'm': r'/\/\\', 'n': '^/',
        'o': '0', 'p': '|D', 'q': '9', 'r': '|2', 's': '$', 't': '7', 'u': '(_)',
        'v': r'\/', 'w': r'\/\/', 'x': '%', 'y': '`/', 'z': '2',
        'A': '4', 'B': '8', 'C': '<', 'D': '|)', 'E': '3', 'F': '|=', 'G': '9',
        'H': '#', 'I': '!', 'J': '_|', 'K': '|<', 'L': '1', 'M': r'/\/\\', 'N': '^/',
        'O': '0', 'P': '|D', 'Q': '9', 'R': '|2', 'S': '$', 'T': '7', 'U': '(_)',
        'V': r'\/', 'W': r'\/\/', 'X': '%', 'Y': '`/', 'Z': '2'
    }
    return ''.join(leet_mapping.get(c, c) for c in custom_string)


def generate_password(counts, pools, exclude_chars, prefix, suffix,
                     total_length, secrets_generator, custom, regex=None):
    """
    Core password generation logic.
    - Validates prefix/suffix against excluded chars.
    - Handles three generation modes: count-based, regex, leet-speak.
    - Enforces total_length constraints.
    - Guarantees no excluded characters appear in the final password.
    """
    # ------------------------------------------------------------------
    # 1. Prefix / suffix validation
    # ------------------------------------------------------------------
    if any(c in exclude_chars for c in prefix + suffix):
        raise ValueError("Prefix or suffix contains excluded characters")

    # ------------------------------------------------------------------
    # 2. Build character pools (filter out excluded chars)
    # ------------------------------------------------------------------
    filtered_pools = {
        k: ''.join(c for c in v if c not in exclude_chars)
        for k, v in pools.items()
    }
    available_chars = ''.join(filtered_pools.values())

    # If we have no characters left and we are not using regex/custom,
    # generation is impossible.
    if not available_chars and not regex and not custom:
        raise ValueError("No available characters after applying exclusions")

    password_chars = []

    # ------------------------------------------------------------------
    # 3. Generation mode selection
    # ------------------------------------------------------------------
    if regex:
        # ----------------------------------------------------------------
        # Regex mode – use rstr to generate a string matching the pattern
        # ----------------------------------------------------------------
        try:
            import rstr
        except ImportError:
            raise RuntimeError("rstr library is required for regex mode")
        generated = rstr.xeger(regex)
        filtered = ''.join(c for c in generated if c not in exclude_chars)
        password_chars.extend(filtered)

        # Adjust length if a total_length is supplied
        if total_length:
            min_req = len(prefix) + len(suffix)
            if total_length < min_req:
                raise ValueError(
                    f"Total length ({total_length}) is less than required by prefix/suffix ({min_req})"
                )
            remaining = total_length - len(password_chars) - len(prefix) - len(suffix)
            if remaining < 0:
                raise ValueError("Regex output exceeds requested total length")
            if remaining > 0:
                if not available_chars:
                    raise ValueError("No characters left to pad regex result")
                password_chars.extend(
                    secrets_generator.choice(available_chars) for _ in range(remaining)
                )

    elif custom:
        # ----------------------------------------------------------------
        # Leet-speak mode
        # ----------------------------------------------------------------
        leet = leet_speak_conversion(custom)
        filtered = ''.join(c for c in leet if c not in exclude_chars)
        password_chars.extend(filtered)

        if total_length:
            min_req = len(prefix) + len(suffix)
            if total_length < min_req:
                raise ValueError(
                    f"Total length ({total_length}) is less than required by prefix/suffix ({min_req})"
                )
            remaining = total_length - len(password_chars) - len(prefix) - len(suffix)
            if remaining < 0:
                raise ValueError("Leet-speak output exceeds requested total length")
            if remaining > 0:
                if not available_chars:
                    raise ValueError("No characters left to pad leet result")
                password_chars.extend(
                    secrets_generator.choice(available_chars) for _ in range(remaining)
                )

    else:
        # ----------------------------------------------------------------
        # Count-based mode
        # ----------------------------------------------------------------
        min_req = sum(counts.values()) + len(prefix) + len(suffix)
        if total_length and total_length < min_req:
            raise ValueError(
                f"Total length ({total_length}) is less than required by counts + prefix/suffix ({min_req})"
            )

        # Pull exact counts from each pool
        for char_type, count in counts.items():
            if count <= 0:
                continue
            pool = filtered_pools.get(char_type)
            if not pool:
                raise ValueError(f"No characters left in {char_type} pool after exclusions")
            password_chars.extend(secrets_generator.choice(pool) for _ in range(count))

        # Pad to total_length if needed
        if total_length:
            remaining = total_length - len(password_chars) - len(prefix) - len(suffix)
            if remaining < 0:
                raise ValueError("Counts exceed requested total length")
            if remaining > 0:
                if not available_chars:
                    raise ValueError("No characters left to pad counts")
                password_chars.extend(
                    secrets_generator.choice(available_chars) for _ in range(remaining)
                )

    # ------------------------------------------------------------------
    # 4. Final shuffle & assembly
    # ------------------------------------------------------------------
    secrets_generator.shuffle(password_chars)
    password = f"{prefix}{''.join(password_chars)}{suffix}"

    # Final sanity check – should never trigger if earlier steps are correct
    if any(c in exclude_chars for c in password):
        raise ValueError("Generated password contains excluded characters")

    return password


def evaluate_password_strength(password):
    """Simple heuristic strength score (0-100)."""
    score = 0
    length = len(password)
    if length >= 8:
        score += 10
    if re.search(r'[a-z]', password):
        score += 10
    if re.search(r'[A-Z]', password):
        score += 10
    if re.search(r'[0-9]', password):
        score += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 10
    if length >= 12:
        score += 20
    if length >= 16:
        score += 20
    if length >= 20:
        score += 20
    return min(score, 100)


def calculate_entropy(password):
    """Estimate Shannon entropy based on used character classes."""
    pool_size = 0
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation)
    if pool_size == 0:
        return 0
    entropy = math.log2(pool_size) * len(password)
    return round(entropy, 2)


def check_password_pwned(password):
    """
    Query Have I Been Pwned? API using k-anonymity.
    Returns a dict with status, SHA-1, breach count and a message.
    """
    try:
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            h, count = line.split(':')
            if h == suffix:
                return {
                    'status': 'Found',
                    'sha1': sha1.lower(),
                    'breach_count': count,
                    'message': 'Identified in data breaches. Change this password immediately.',
                    'color': 'red'
                }
        return {
            'status': 'Not Found',
            'sha1': sha1.lower(),
            'breach_count': '0',
            'message': 'Not detected in any known breaches.',
            'color': 'green'
        }
    except requests.RequestException as e:
        return {
            'status': 'Error',
            'message': f'Network error while contacting HIBP: {e}',
            'color': 'red'
        }
    except Exception as e:
        return {
            'status': 'Error',
            'message': f'Unexpected error: {e}',
            'color': 'red'
        }


# ----------------------------------------------------------------------
# Flask routes
# ----------------------------------------------------------------------
@app.route('/', methods=['GET'])
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/generate', methods=['POST'])
def generate():
    """
    Generate one or more passwords based on client parameters.
    - Validates JSON payload and all numeric inputs.
    - Centralises error responses (400) with a clear message.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid JSON payload'}), 400

        # ----------------------------------------------------------------
        # Extract and validate numeric fields
        # ----------------------------------------------------------------
        def get_int(key, default=0, min_val=None):
            val = data.get(key, default)
            try:
                i = int(val)
                if min_val is not None and i < min_val:
                    raise ValueError
                return i
            except (ValueError, TypeError):
                raise ValueError(f"'{key}' must be an integer >= {min_val if min_val is not None else 0}")

        numbers = get_int('numbers', min_val=0)
        lowercase = get_int('lowercase', min_val=0)
        uppercase = get_int('uppercase', min_val=0)
        special_chars = get_int('special_chars', min_val=0)
        amount = get_int('amount', default=1, min_val=1)
        total_length = get_int('total_length', min_val=0)

        # ----------------------------------------------------------------
        # Textual fields (may be empty)
        # ----------------------------------------------------------------
        regex = data.get('regex', '').strip()
        prefix = data.get('prefix', '').strip()
        suffix = data.get('suffix', '').strip()
        custom = data.get('custom', '').strip()
        exclude_chars = data.get('exclude_chars', '').strip()
        output_format = data.get('output_format', 'txt').lower()
        if output_format not in ('txt', 'json'):
            raise ValueError("output_format must be 'txt' or 'json'")

        # ----------------------------------------------------------------
        # Seed handling (optional)
        # ----------------------------------------------------------------
        seed = data.get('seed')
        if seed:
            try:
                seed = int(seed)
                random.seed(seed)
                secrets_generator = random.Random(seed)
            except (ValueError, TypeError):
                raise ValueError("seed must be an integer")
        else:
            secrets_generator = secrets.SystemRandom()

        # ----------------------------------------------------------------
        # Build character pools – only include pools that are requested
        # ----------------------------------------------------------------
        pools = {}
        if numbers or regex or custom:
            pools['digits'] = string.digits
        if lowercase or regex or custom:
            pools['lowercase'] = string.ascii_lowercase
        if uppercase or regex or custom:
            pools['uppercase'] = string.ascii_uppercase
        if special_chars or regex or custom:
            pools['special'] = string.punctuation

        # If no pools are defined (all counts zero and no regex/custom),
        # fall back to all pools so the user can still generate something.
        if not pools and not custom and not regex:
            pools = {
                'digits': string.digits,
                'lowercase': string.ascii_lowercase,
                'uppercase': string.ascii_uppercase,
                'special': string.punctuation
            }

        # ----------------------------------------------------------------
        # Generate each requested password
        # ----------------------------------------------------------------
        passwords = []
        counts = {
            'digits': numbers,
            'lowercase': lowercase,
            'uppercase': uppercase,
            'special': special_chars
        }

        for _ in range(amount):
            pw = generate_password(
                counts, pools, exclude_chars, prefix, suffix,
                total_length, secrets_generator, custom, regex=regex
            )
            strength = evaluate_password_strength(pw)
            entropy = calculate_entropy(pw)
            passwords.append({
                'password': pw,
                'strength': strength,
                'entropy': entropy
            })

        return jsonify({'passwords': passwords})

    except ValueError as ve:
        # Validation errors from own logic
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        # Unexpected errors – log for debugging (Flask debug mode will show)
        app.logger.error(f"Unexpected error in /generate: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/check_pwned', methods=['POST'])
def check_pwned():
    """Check a single password against Have I Been Pwned?."""
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            return jsonify({'error': 'Password is required'}), 400
        password = data['password']
        if not isinstance(password, str) or not password.strip():
            return jsonify({'error': 'Password must be a non-empty string'}), 400

        result = check_password_pwned(password.strip())
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error in /check_pwned: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/download', methods=['POST'])
def download():
    """
    Return generated passwords as a downloadable file.
    Expected JSON: { "passwords": [...], "format": "txt"|"json" }
    """
    try:
        data = request.get_json()
        if not data or 'passwords' not in data:
            return jsonify({'error': 'Missing passwords list'}), 400

        passwords = data['passwords']
        fmt = data.get('format', 'txt').lower()
        if fmt not in ('txt', 'json'):
            return jsonify({'error': "format must be 'txt' or 'json'"}), 400

        output = io.StringIO()
        if fmt == 'json':
            json_data = {'passwords': [p['password'] for p in passwords]}
            output.write(json.dumps(json_data, indent=4, ensure_ascii=False))
            mimetype = 'application/json'
            filename = 'passwords.json'
        else:
            lines = [
                f"{p['password']} ({p.get('strength', '?')}%, {p.get('entropy', '?')})"
                for p in passwords
            ]
            output.write('\n'.join(lines))
            mimetype = 'text/plain'
            filename = 'passwords.txt'

        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        app.logger.error(f"Error in /download: {e}")
        return jsonify({'error': 'Failed to create download'}), 500


# ----------------------------------------------------------------------
# Application entry point
# ----------------------------------------------------------------------
if __name__ == '__main__':
    app.run()
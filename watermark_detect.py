import re

def detect_watermarks(text):
    # Pattern for common invisible characters
    pattern = r'[\u200B-\u200D\uFEFF\u00AD\u2060]'

    matches = re.findall(pattern, text)

    print(f"Watermarks found: {len(matches)}")
    for char in set(matches):
        count = matches.count(char)
        print(f"  {repr(char)}: {count} occurrences")

    return len(matches) > 0

def detect_watermarks_in_file(filepath):
    """Scan a Python file for invisible watermark characters."""
    print(f"\n{'='*50}")
    print(f"Scanning: {filepath}")
    print('='*50)

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.split('\n')
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        return False

    # Extended pattern for more invisible/suspicious characters
    watermark_chars = {
        '\u200B': 'Zero Width Space',
        '\u200C': 'Zero Width Non-Joiner',
        '\u200D': 'Zero Width Joiner',
        '\uFEFF': 'Byte Order Mark (BOM)',
        '\u00AD': 'Soft Hyphen',
        '\u2060': 'Word Joiner',
        '\u180E': 'Mongolian Vowel Separator',
        '\u200E': 'Left-to-Right Mark',
        '\u200F': 'Right-to-Left Mark',
        '\u202A': 'Left-to-Right Embedding',
        '\u202B': 'Right-to-Left Embedding',
        '\u202C': 'Pop Directional Formatting',
        '\u202D': 'Left-to-Right Override',
        '\u202E': 'Right-to-Left Override',
        '\u2061': 'Function Application',
        '\u2062': 'Invisible Times',
        '\u2063': 'Invisible Separator',
        '\u2064': 'Invisible Plus',
    }

    pattern = r'[' + ''.join(watermark_chars.keys()) + ']'

    total_found = 0
    findings = {}
    line_findings = []

    for line_num, line in enumerate(lines, 1):
        matches = re.findall(pattern, line)
        if matches:
            for char in matches:
                char_name = watermark_chars.get(char, 'Unknown')
                findings[char] = findings.get(char, 0) + 1
                total_found += 1
            line_findings.append((line_num, len(matches), line[:80]))

    # Report results
    print(f"\nTotal watermark characters found: {total_found}")

    if findings:
        print("\n--- Character Breakdown ---")
        for char, count in sorted(findings.items(), key=lambda x: -x[1]):
            char_name = watermark_chars.get(char, 'Unknown')
            print(f"  {repr(char)} ({char_name}): {count} occurrences")

        print("\n--- Lines with Watermarks ---")
        for line_num, count, preview in line_findings[:10]:
            print(f"  Line {line_num}: {count} char(s) | {preview}...")
        if len(line_findings) > 10:
            print(f"  ... and {len(line_findings) - 10} more lines")
    else:
        print("No invisible watermark characters detected.")

    return total_found > 0

# Usage
if __name__ == "__main__":
    # Test with inline text
    print("=== Inline Text Check ===")
    text = "Your ChatGPT text here"
    has_watermarks = detect_watermarks(text)

    # Scan phishing_scanner.py
    print("\n=== File Scan: phishing_scanner.py ===")
    detect_watermarks_in_file('phishing_scanner.py')
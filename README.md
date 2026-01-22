# Standard Notes TOTP Converter
A Python script for converting a list of TOTP URIs to the JSON format used by Standard Notes's "Authenticator" note type, and vice versa.

## Usage
You can tell the script to import to or export from Standard Notes.
### Importing
When importing, you provide a file path to a text file containing a list of TOTP URIs. They start with `otpauth://` and will usually contain a service name, account name (username/email address), and a secret code. You can also use certain types of password manager CSV export files (only confirmed to work with Apple Passwords on MacOS), or a Bitwarden/Vaultwarden JSON file.

If the script can't find an account name, you will be asked for one. If it can't find the service name, it will be replaced by `[Unknown Service]`.

The output when importing will be in JSON that you can use in Standard Notes. To import into SN:
1. Open the text file on your computer (using Notepad, TextEdit, etc)
2. Select the entire content of the text file and copy it
3. Create a new note in Standard Notes and set its type to Plain Text
4. Paste the contents of the text file into Standard Notes
5. Change the note type to Authenticator

### Exporting
The input will be a file path to a text file containing the JSON data from Standard Notes. The script will convert the JSON data back into a list of TOTP URIs in a text file that can be imported by some authenticator apps. You can also use a QR code generator on the URIs to create the TOTP QR code that can be used to add the codes to an authenticator app on your phone.

# Security Considerations
Do not handle your TOTP codes on computers you do not trust, and I would recommend deleting files containing the information from your computer when done to make sure your codes don't fall into the wrong hands. If someone has your password and the files with the TOTP secrets in them, they can sign into your accounts.

This script does not use the Internet at all when converting codes, the conversion is handled entirely in the script.

# Credits/License
The code in this repository is licensed under the MIT License.

The trademark of Standard Notes is owned by Standard Notes Ltd. The software itself is open-source at https://github.com/standardnotes.
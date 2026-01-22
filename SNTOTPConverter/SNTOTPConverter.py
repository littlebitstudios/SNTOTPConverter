from urllib.parse import urlparse, parse_qs
import json
import os
import sys
import csv

def uri_to_object(uri:str):
    uri_converted = urlparse(uri)._replace(path=urlparse(uri).path.replace('%20', ' ').replace('%3A', ':').replace('%40', '@')).geturl()
    
    if uri_converted.startswith("otpauth://totp"):
        parsed_url = urlparse(uri_converted)
        params = parse_qs(parsed_url.query)
        
        totp_object = {
            "service": "",
            "account": "",
            "secret": params.get('secret', [''])[0],
            "notes": ""
        }
        
        if ":" in parsed_url.path:
            service_account = parsed_url.path[1:].split(':')
            totp_object["service"] = service_account[0]
            totp_object["account"] = service_account[1]
        elif "issuer" in params:
            if isinstance(params["issuer"], list):
                totp_object["service"] = params["issuer"][0]
            else:
                totp_object["service"] = params["issuer"]
                
            totp_object["account"] = input("Enter a username (or email) for your "+totp_object["service"]+" account: ")
        else:
            totp_object["service"] = parsed_url.path if parsed_url.path else "[Unknown Service]"
            totp_object["account"] = input("Enter a username (or email) for your "+totp_object["service"]+" account: ")
            
        return totp_object
    elif uri_converted.startswith("otpauth://"):
        print("This is a OTP URI, but it may be using an unsupported protocol, such as HOTP.")
    else:
        print("Invalid TOTP URI.")
        
def object_to_uri(totp_object:dict):
    if all(key in totp_object for key in ("service", "account", "secret")):
        service = totp_object["service"]
        account = totp_object["account"]
        secret = totp_object["secret"]
        uri = f"otpauth://totp/{service}:{account}?secret={secret}&issuer={service}"
        return uri
    else:
        print("Invalid TOTP object. Missing required keys.")
        
def secret_from_uri(uri: str):
    if not uri:
        return ""
    parsed_url = urlparse(uri)
    if not parsed_url.scheme == "otpauth" or not parsed_url.netloc == "totp":
        return ""
    params = parse_qs(parsed_url.query)
    return params.get('secret', [''])[0]

def save_sntotp_json(objectlist:list):
    output_file_path = ""
    if len(sys.argv) > 3:
        output_file_path = sys.argv[3]
    else:
        print("No output path provided")
        exit(1)
        
    if not "." in output_file_path:
        output_file_path = output_file_path + ".json"

    with open(os.path.expanduser(output_file_path), 'w') as output_file:
        json.dump(objectlist, output_file, indent=4)

    print(f"The input was converted to SN TOTP JSON, saved to {output_file_path}")
    print("To save the codes to Standard Notes, make a new note, set the note to Plain Text, paste the contents of the output file into SN, then change the note type to Authenticator.")

def main():
    print("Standard Notes TOTP Converter by LittleBit")
    
    user_choice = ""
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "import":
            user_choice = "i"
        elif sys.argv[1].lower() == "export":
            user_choice = "e"
        elif sys.argv[1] in ("--help", "-h"):
            print("Import and export files for use with Standard Notes, TOTP apps, or password managers")
            print("")
            print("Import: sntotpconverter import <input CSV/TXT/JSON> <output JSON>")
            print("Import a TOTP URI list (.txt), Apple Passwords CSV, or a Bitwarden/Vaultwarden JSON")
            print("")
            print("Export: sntotpconverter export <input JSON> <output TXT>")
            print("Outputs a TOTP URI list (.txt) for use with TOTP apps")
            print("")
            print("Running the program with --help or -h as the first argument shows this help message")
            exit(0)
    else:
        print("Unknown command, run sntotpconverter -h for instructions")
        exit(1)

    if user_choice.lower() == "i":
        user_file_path = ""
        if len(sys.argv) > 2:
            user_file_path = sys.argv[2]
        else:
            print("No input TXT/CSV/JSON provided")
            exit(1)

        # Only run this if the file is a .txt
        if user_file_path.lower().endswith('.txt'):
            with open(os.path.expanduser(user_file_path)) as f:
                totp_object_list = []
                for line in f:
                    line = line.strip()
                    if line:
                        totp_object = uri_to_object(line)
                    if totp_object:
                        totp_object_list.append(totp_object)

            save_sntotp_json(totp_object_list)
        # CSV file handling
        elif user_file_path.lower().endswith('.csv'):
            required_fields = {"Title", "Username", "Password", "Notes", "OTPAuth"}
            with open(user_file_path, newline='') as input_file:
                reader = csv.DictReader(input_file)
                if not reader.fieldnames or not required_fields.issubset(reader.fieldnames):
                    print(f"CSV file must contain the following columns: {', '.join(required_fields)}")
                    print(f"The CSV importer only supports CSV files generated by Apple Passwords.")
                    print(f"Using Bitwarden/Vaultwarden? Export as a JSON (not encrypted) file instead of CSV.")
                    return
                totp_object_list = []
                seen = set()
                for row in reader:
                    if not row['OTPAuth']:
                        continue
                    key = (row['Title'], row['Username'], secret_from_uri(row['OTPAuth']))
                    if key in seen:
                        print(f"Skipping duplicate: Service='{row['Title']}', Account='{row['Username']}'")
                        continue
                    seen.add(key)
                    totp_object = {
                        'service': row['Title'],
                        'account': row['Username'],
                        'secret': secret_from_uri(row['OTPAuth']),
                        'password': row['Password'],
                        'notes': row['Notes']
                    }
                    totp_object_list.append(totp_object)
            
            save_sntotp_json(totp_object_list)
        elif user_file_path.lower().endswith('.json'):
            data = {}
            with open(user_file_path) as f:
                data = json.load(f)
                
            if not "encrypted" in data or not "items" in data:
                print("That doesn't look like a Bitwarden JSON file.")
                print("If you have a Standard Notes TOTP JSON file that you want to convert to a TOTP URI list, use the export option.")
                exit(1)
                
            if data.get("encrypted"):
                print("The file appears to be encrypted (the \"encrypted\" key is a truthy value).")
                print("Make sure that you export JSON from Bitwarden/Vaultwarden WITHOUT encryption.")
                exit(1)
                
            totp_object_list = []
            for item in data.get("items"):
                if "login" in item:
                    if item.get("login",{}).get("totp"):
                        totp_object = {
                            'service': item.get("name"),
                            'account': item.get("login",{}).get("username"),
                            'secret': secret_from_uri(item.get("login",{}).get("totp")),
                            'password': item.get("login",{}).get("password"),
                            'notes': item.get("login",{}).get("notes")
                        }
                    
                        if not totp_object.get("account"):
                            totp_object["account"] = input(f"Enter a username (or email) for your {totp_object.get("service")} account: ")
                        
                        totp_object_list.append(totp_object)
            
            save_sntotp_json(totp_object_list)
        else:
            print("Only TXT, CSV, and JSON files are supported for import.")
    elif user_choice.lower() == "e":
        
        user_file_path = ""
        if len(sys.argv) > 2:
            user_file_path = sys.argv[2]
            print(f"Continuing with argument (input file path: {sys.argv[2]})")
        else:
            print("No input JSON provided")
            exit(1)

        with open(os.path.expanduser(user_file_path)) as f:
            totp_object_list = json.load(f)
            totp_uri_list = []
            for totp_object in totp_object_list:
                totp_uri_list.append(object_to_uri(totp_object))
            
            output_file_path = ""
            if len(sys.argv) > 3:
                output_file_path = sys.argv[3]
            else:
                print("No output file path provided")
                exit(1)
            
            with open(os.path.expanduser(output_file_path), 'w') as output_file:
                for uri in totp_uri_list:
                    output_file.write(uri + '\n')

            print(f"TOTP URIs exported from SN TOTP JSON and saved to {output_file_path}")
            print("You may import them using authenticator apps that support importing from URI lists")
            
if __name__ == "__main__":
    main()
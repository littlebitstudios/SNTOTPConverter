from urllib.parse import urlparse, parse_qs
import json
import os
import sys

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
                
            totp_object["account"] = input("Enter an email or username for your "+totp_object["service"]+" account: ")
        else:
            totp_object["service"] = parsed_url.path if parsed_url.path else "[Unknown Service]"
            totp_object["account"] = input("Enter an email or username for your "+totp_object["service"]+" account: ")
            
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

def main():
    print("Standard Notes TOTP Converter by LittleBit")
    
    user_choice = ""
    if len(sys.argv) > 1:
        if sys.argv[1].lower() == "import":
            user_choice = "i"
            print("Continuing with argument (import)")
        elif sys.argv[1].lower() == "export":
            user_choice = "e"
            print("Continuing with argument (export)")
    else:
        user_choice = input("Are you (i)mporting to or (e)xporting from Standard Notes?")

    if user_choice.lower() == "i":
        
        user_file_path = ""
        if len(sys.argv) > 2:
            user_file_path = sys.argv[2]
            print(f"Continuing with argument (input file path: {sys.argv[2]})")
        else:
            user_file_path = input("Enter the file path of a text file containing a list of TOTP URIs: ")

        with open(os.path.expanduser(user_file_path)) as f:
            totp_object_list = []
            for line in f:
                line = line.strip()
                if line:
                    totp_object = uri_to_object(line)
                    if totp_object:
                        totp_object_list.append(totp_object)

            output_file_path = ""
            if len(sys.argv) > 3:
                output_file_path = sys.argv[3]
                print(f"Continuing with argument (output file path: {sys.argv[3]})")
            else:
                output_file_path = input("Enter the file path to save the JSON output: ")
                if not "." in output_file_path:
                    output_file_path = output_file_path+".json"

            with open(os.path.expanduser(output_file_path), 'w') as output_file:
                json.dump(totp_object_list, output_file, indent=4)

            print(f"Your TOTP URI list was converted to JSON, saved to {output_file_path}")
            print("To save the codes to Standard Notes, make a new note, set the note to Plain Text, paste the contexts of the output file into SN, then change the note type to Authenticator.")
    elif user_choice.lower() == "e":
        
        user_file_path = ""
        if len(sys.argv) > 2:
            user_file_path = sys.argv[2]
            print(f"Continuing with argument (input file path: {sys.argv[2]})")
        else:
            user_file_path = input("Enter the file path of a text file containing a list of TOTP URIs: ")

        with open(os.path.expanduser(user_file_path)) as f:
            totp_object_list = json.load(f)
            totp_uri_list = []
            for totp_object in totp_object_list:
                totp_uri_list.append(object_to_uri(totp_object))
            
            output_file_path = ""
            if len(sys.argv) > 3:
                output_file_path = sys.argv[3]
                print(f"Continuing with argument (output file path: {sys.argv[3]})")
            else:
                output_file_path = input("Enter the file path to save the text output: ")
                if not "." in output_file_path:
                    output_file_path = output_file_path+".txt"
            
            with open(os.path.expanduser(output_file_path), 'w') as output_file:
                for uri in totp_uri_list:
                    output_file.write(uri + '\n')

            print(f"TOTP URIs exported from JSON and saved to {output_file_path}")
            print("You may import them using authenticator apps that support importing from URI lists")
            
if __name__ == "__main__":
    main()
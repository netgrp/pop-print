#!/usr/bin/python3
# -*- coding: utf-8, vim: expandtab:ts=4 -*-

import os
import re
import threading
import subprocess
import ipaddress
from urllib.parse import urlparse
import time
import requests
import uuid as Uuid
import hashlib
from requests.auth import HTTPBasicAuth
from apscheduler.schedulers.background import BackgroundScheduler
import cryptography
import secrets

from flask import Flask, request, redirect, url_for, make_response
from flask_restful import Resource, Api
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

load_dotenv()

knet_api_base_url = "https://api.k-net.dk/v2/"
print_hostname = "print.pop.dk"
print_scheme = "https"

# Get API username and password from environment variables
knet_api_username = os.environ.get("KNET_API_USERNAME")
knet_api_password = os.environ.get("KNET_API_PASSWORD")
crypt_key = os.environ.get("AES_CRYPT_KEY")
initialization_vector = os.environ.get("INITIALIZATION_VECTOR").encode()
assert crypt_key != None, "AES_CRYPT_KEY environment variable not set"

algorithm = algorithms.AES(crypt_key.encode())

mode = modes.CTR(initialization_vector)
cipher = Cipher(algorithm, mode)

UPLOAD_FOLDER = "/tmp/"
ALLOWED_EXTENSIONS = {"pdf"}
PRINTER = "default"  # Printer name from lpstat -p -d or 'default' for the system's default printer
DUPLEX_OPTIONS = {"1sided": "1Sided", "2sided": "2Sided"}
COLOR_OPTIONS = {"auto": "", "color": "Color", "grayscale": "Grayscale"}
ORIENTATION = {
    "portrait": "-o orientation-requested=3",
    "landscape": "-o orientation-requested=4",
}
SIZE = {"A4": "A4", "A3": "A3"}
RANGE_RE = re.compile("([0-9]+(-[0-9]+)?)(,([0-9]+(-[0-9]+)?))*$")

# lock to control access to variable
print_lock = threading.Lock()
LOGIN_TIME = 10 * 60

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
api = Api(app)

print_upload_form = """
<!DOCTYPE html>
<html>
<head>
<style>
body, html {

    width: 100%;
    height: 100%;
    margin: 0;
    padding: 0;
    display:table;
}
body {
    display:table-cell;
    vertical-align:middle;
}
form {
    display:table;/* shrinks to fit conntent */
    margin:auto;
}
</style>
</head>
<body>

<form action="" method="post" enctype="multipart/form-data">
    <p>
        Upload PDF to print: <br/>
        <input type="file" name="uploadedPDF" accept=".pdf">
    </p>
    <p>
        Duplex: <br/>
        <input type="radio" name="duplex" value="1sided" > One sided<br>
        <input type="radio" name="duplex" value="2sided" checked> Two sided<br>
    </p>
    <p>
        Color mode: <br/>
        <input type="radio" name="color" value="auto" checked> Auto<br>
        <input type="radio" name="color" value="color"> Color<br>
        <input type="radio" name="color" value="grayscale"> Grayscale<br>
    </p>
    <p>
       Range: <br/>
       <input type="text" name="range" placeholder="1-5,8,11-13">
    </p>
    <p>
        Size: <br/>
        <input type="radio" name="size" value="A4" checked> A4<br>
        <input type="radio" name="size" value="A3"> A3<br>
    </p>
    <p>
        Orientation: <br/>
        <input type="radio" name="orientation" value="portrait" checked> Portrait<br>
        <input type="radio" name="orientation" value="landscape"> Landscape<br>
    </p>
    <p>
       Copies: <br/>
       <input type="number" name="copies" placeholder="1">
    </p>
    <p>
        <input type="submit" value="Print" name="print">
    </p>
</form>

</body>
</html>
"""

login_form = """<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Login Page</title>
                <style>
                    body {
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                    }
                    
                    form {
                        text-align: center;
                        padding: 20px;
                        border: 1px solid #ccc;
                        border-radius: 5px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
                    }

                    label, input {
                        display: block;
                        margin: 10px 0;
                    }
                </style>
            </head>
            <body>  
                <form action="{url}" method="post">
                    <h1>Login</h1>
                    <label for="username">Brugernavn:</label>
                    <input type="text" id="username" name="username" required><br><br>
                    <label for="password">Kodeord:</label>
                    
                    <input type="password" id="password" name="password" required><br><br>
                    <input name="login" type="submit" value="Login">
                </form>
            </body>
            </html>
        """


def printhtml(
    duplex, color, page_range, orientation, size, copies, pdf, pdf_filename
):
    command = ["/usr/bin/lp"]

    if PRINTER != "default":
        command.extend(["-d", PRINTER])

    if duplex != "none":
        command.extend(["-o", "KMDuplex=" + DUPLEX_OPTIONS[duplex]])

    if color != "auto":
        command.extend(["-o", "SelectColor=" + COLOR_OPTIONS[color]])

    if SIZE != "A4":
        command.extend(["-o", "PageSize=" + SIZE[size]])

    if len(page_range) > 0:
        command.extend(["-P", page_range])

    command.extend(ORIENTATION[orientation].split())

    if copies > 1:
        command.extend(["-n", str(copies)])

    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], pdf_filename)
    command.append(pdf_path)

    pdf.save(pdf_path)
    ret = subprocess.run(command, stderr=subprocess.PIPE)
    os.remove(pdf_path)

    if ret.returncode != 0:
        err_msg = ret.stderr.decode("UTF-8").rstrip()
        return "Printing error: {0}".format(err_msg), 500
    return None


class PrintREST(Resource):
    @staticmethod
    @app.route("/print", methods=["POST"])
    def printhtml():
        print("printing")
        pdf = request.files["uploadedPDF"]
        pdf_filename = secure_filename(pdf.filename)

        duplex = request.form["duplex"]
        color = request.form["color"]
        page_range = request.form["range"]
        orientation = request.form["orientation"]
        size = request.form["size"]
        copies = request.form["copies"]
        if copies == "":
            copies = 1
        else:
            copies = int(copies)

        if (
            duplex in DUPLEX_OPTIONS
            and pdf
            and pdf.filename.rsplit(".", 1)[1] in ALLOWED_EXTENSIONS
            and (len(page_range) == 0 or RANGE_RE.match(page_range))
            and orientation in ORIENTATION
            and copies > 0
        ):
            with print_lock:
                ret = printhtml(
                    duplex,
                    color,
                    page_range,
                    orientation,
                    size,
                    copies,
                    pdf,
                    pdf_filename,
                )
            return print_upload_form
            """ if ret is not None:
                return ret

            return 'Printing "{0}" to "{1}" with duplex "{2}" range "{3}" in "{4}" orientation {5} times...'.format(
                pdf_filename, PRINTER, duplex, page_range, orientation, copies)
        return 'Some parameters wrong: {0} {1}'.format(duplex, pdf.filename), 400 """


# redirect / to /login page
@app.route("/")
def login_and_printhtml():
    # try to get the login cookie

    login_cookie = request.cookies.get("login")

    # If cookie is set, check if it is valid
    if login_cookie != None:
        print(login_cookie)
        decryptor = cipher.decryptor()
        try:
            message_decrypted = (
                decryptor.update(bytes.fromhex(login_cookie)) + decryptor.finalize()
            )
        except cryptography.exceptions.InvalidTag:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))
        except ValueError:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))

        # Check if the cookie is valid

        try:
            print(f"Decrypted Message: {message_decrypted.decode()}")
            if time.time() - float(message_decrypted.decode()) < LOGIN_TIME:
                return print_upload_form
        except ValueError:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))
        except TypeError:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))
    # Otherwise interface is not yet logged in, Offer login

    return login_form.replace("{url}", url_for("login_and_printhtml_post"))

def login():

    login_cookie = request.cookies.get("login")

    # If cookie is set, check if it is valid
    if login_cookie != None:
        print(login_cookie)
        print("found cookie")
        decryptor = cipher.decryptor()
        try:
            message_decrypted = (
                decryptor.update(bytes.fromhex(login_cookie)) + decryptor.finalize()
            )
        except cryptography.exceptions.InvalidTag:
            pass
        except ValueError:
            pass

        # Check if the cookie is valid
        print("Decrypted cookie")

        try:
            print(f"Decrypted Message: {message_decrypted.decode()}")
            if time.time() - float(message_decrypted.decode()) < LOGIN_TIME:
                print("actually printing")
                return PrintREST.printhtml()
        except ValueError:
            pass
        except TypeError:
            pass
        # Otherwise interface is not yet logged in, Offer login
    username = request.form.get("username")
    password = request.form.get("password")
    user_response = requests.get(
        knet_api_base_url + "network/user/?username=" + username,
        auth=HTTPBasicAuth(knet_api_username, knet_api_password),
    )

    # Check if we got a 200 OK
    # If not we cannot check the login and we should fail right here
    if user_response.status_code != 200:
        return "login failed", 500

    # There should only be one response.
    # If less then no user was found.
    # If more then we cannot check password correctly.
    # TODO Handle lack of ['count'] key in a graceful way
    if user_response.json()["count"] != 1:
        return "Login failed", 500

    # Get password to compare. First result contain password with salt
    password_from_knet = user_response.json()["results"][0]["password"]

    # Get the password parts. Format should be sha1$[SALT]$[HASH]
    pwd_parts = password_from_knet.split("$")

    # We check that sha1 was used. If not we cannot check the password
    if pwd_parts[0] != "sha1":
        return "Login failed", 500

    # Perform the hashing with the given password and the salt from k-net
    hash_result = hashlib.sha1(bytes(pwd_parts[1] + password, "utf-8")).hexdigest()

    # Check aginst the salt+hash stored at K-Net
    # If not OK: Stop here
    if hash_result != pwd_parts[2]:
        # Reject if login is invalid
        return "Login failed", 500

    # Get the IP address of the user
    user_ip = request.headers.get("X-Real-IP")

    # save login cookie
    encryptor = cipher.encryptor()
    message_encrypted = (
        encryptor.update(str(time.time()).encode()) + encryptor.finalize()
    )

    # print(f"Secret Key: {crypt_key}")
    # print(f"Public Initialization Vector: {initialization_vector.hex()}")
    print(f"Encrypted Message: {message_encrypted.hex()}")

    # Save the login cookie
    resp = make_response(print_upload_form)
    resp.set_cookie(
        "login",
        value=message_encrypted.hex(),
        max_age=LOGIN_TIME,
        secure=True,
        httponly=True,
    )
    print("setting cookie")

    return resp


@app.route("/", methods=["POST"])
def login_and_printhtml_post():
    # Get form name
    if "login" in request.form:
        print("logging in")
        return login()
    elif "print" in request.form:

        login_cookie = request.cookies.get("login")

        # If cookie is set, check if it is valid
        if login_cookie != None:
            print(login_cookie)
            print("found cookie")
            decryptor = cipher.decryptor()
            try:
                message_decrypted = (
                    decryptor.update(bytes.fromhex(login_cookie)) + decryptor.finalize()
                )
            except cryptography.exceptions.InvalidTag:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))
            except ValueError:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))

            # Check if the cookie is valid
            print("Decrypted cookie")

            try:
                print(f"Decrypted Message: {message_decrypted.decode()}")
                if time.time() - float(message_decrypted.decode()) < LOGIN_TIME:
                    print("actually printing")
                    return PrintREST.printhtml()
            except ValueError:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))
            except TypeError:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))
            # Otherwise interface is not yet logged in, Offer login
        return login_form.replace("{url}", url_for("login_and_printhtml_post"))
    else:
        return "Unknown form", 500


if __name__ == "__main__":
    app.run(debug=False)

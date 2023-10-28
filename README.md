# pop-print
This is an implementation for a print server for our dorm. It uses CUPS for printing from a local server. 
The application is created using flask in python and accesses CUPS using python subcommands and the lp command.

# .env file
A file with environment variables must be included in /app. Example below:
  
    KNET_API_USERNAME = 'api name thingy'
    KNET_API_PASSWORD = 'api password thingy' 
    AES_CRYPT_KEY = 'some random bytes' (32 bytes)
    INITIALIZATION_VECTOR = 'fewer random bytes' (16 bytes)


# TODO
- [x] Cookie check. Needs to check login cookie before every print.
- [x] Increase nginx file size limit for larger prints.
- [ ] Check IV encryption. Currently we a using a static initialization vector
- [ ] Prevent multi print. Refreshes to the page might resubmit the print form
- [ ] Better frontend. Maybe bootstrap or tailwindcss.
- [ ] Check printing options for hole punch, binding, tray selection and paper size.

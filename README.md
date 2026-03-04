# pop-print
This is an implementation for a print server for our dorm. It uses CUPS for printing from a local server. 
The application is created using axum in Rust and printing using the ipp.rs to submit jubs to CUPS.

# Environment variables

The program requires some environment variables to be set.

If the `dotenv` feature is enabled, `.env` in the pwd will be loaded.
  
    KNET_API_USERNAME = 'api name thingy'
    KNET_API_PASSWORD = 'api password thingy' 
    AES_CRYPT_KEY = 'some random bytes'
    INITIALIZATION_VECTOR = 'fewer random bytes'
    PRINTER_URI = 'http://localhost:631/printers/PRINTER_NAME_HERE'
The AES_CRYPT_KEY should be 32 bytes when encoded as UTF-8, and the INITIALIZATION_VECTOR should be 16 bytes.

# TODO
- [x] Cookie check. Needs to check login cookie before every print.
- [x] Increase nginx file size limit for larger prints.
- [ ] Check IV encryption. Currently we a using a static initialization vector
- [ ] Prevent multi print. Refreshes to the page might resubmit the print form
- [ ] Better frontend. Maybe bootstrap or tailwindcss.
- [ ] Check printing options for hole punch, binding, tray selection and paper size.

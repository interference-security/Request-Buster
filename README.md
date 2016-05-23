# Request-Buster
This BurpSuite extension is based on the work of Burpy available here: https://github.com/debasishm89/burpy

What this extension can do:

- CSRF testing: It accepts an Anti-CSRF token and a request failure message. For every request Anti-CSRF token is removed and request is resent followed by checking response for CSRF failure message.

- Add/Remove HTTP headers

- Add/Remove request parameters

- Generate HTML report

## How to use:

Modify line 68-90 and 128-144 for this extension to work according to your requirements.

Import the Python file in Burp using "Extender".

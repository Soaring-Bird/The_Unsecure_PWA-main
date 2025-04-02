from flask import Flask, render_template, request, redirect, abort, session
import user_management as dbHandler
from urllib.parse import urlparse, urljoin
from flask_wtf import CSRFProtect  
from flask_limiter import Limiter 
from flask_limiter.util import get_remote_address
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sM4SVhK8FYJAS692DqhA8UuJ2BaZmpLJ'  

"""
CSRF tokens are generated using the SECRET_KEY defined in the application (app.config['SECRET_KEY']). 
{{ csrf_token() }} is used in HTML forms to generate a unique hidden token for each request.
During form submission, Flask-WTF automatically verifies the token against expected token in stored session. 
If this is missing or invalid, a 400 error is returned.
"""
csrf = CSRFProtect(app)  # Enables CSRF protection globally
# only disable CSRF for testing purposes.
app.config['WTF_CSRF_ENABLED'] = False

# Initialize rate limiter with remote address-based key. This slows down brute-force attacks, by decreasing the number of requests per second.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour", "10 per minute"]
)

# Content Security Policy header to prevent XSS and other attacks.
@app.after_request
def set_csp(response):
    # Build the CSP header as a single-line string
    csp_policy = (
        "default-src 'none'; "  # Block all content by default
        "script-src 'self' 'nonce-<RANDOM_NONCE>'; "  # Allow scripts only from same origin and inline scripts with a valid nonce (prevent XSS)
        "style-src 'self'; "  # Allow styles from same origin
        "img-src 'self' data:; "  # Allow images from same origin and base64 data images
        "font-src 'self'; "  # Allow fonts only from same origin
        "frame-src 'none'; "  # Disallow embedding in frames (clickjacking protection)
        "base-uri 'self'; "  # Restrict <base> element usage to same origin
        "form-action 'self'; "  # Allow form submissions only to same origin
        "manifest-src 'self'; "  # Allow service worker manifests only from same origin
        "frame-ancestors 'none'; "  # Prevent your site from being embedded in other sites
    )
    response.headers['Content-Security-Policy'] = csp_policy.strip() #strip to avoid \n issues
    return response

def is_safe_url(target):
    """
    Validate the URL to prevent open redirect vulnerabilities.
    This function ensures that redirections only occur within the same domain,
    hence mitigating open redirect attacks.
    """
    #Consider http://127.0.0.1:5000/?url=https://google.com 
    ref_url = urlparse(request.host_url)  # Breaks down the base URL into its components.
    test_url = urlparse(urljoin(request.host_url, target))  # Joins and parses the target URL.
    #urljoin() combines request.host_url and the target URL to form a complete URL. E.g. if path is relative it will convert to : http://localhost:5000/google
    #Since https://google.com is already an absolute URL, urljoin() doesn't change it. urlparse() breaks it apart to scheme, netlock and path
    # Returns True only if the scheme is HTTP/HTTPS and the netlock matches, kept for future extensibility to https.
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc
    

@app.route("/success.html", methods=["POST", "GET"])
@limiter.limit("10 per minute")  # Limit for DoS protection
def addFeedback():
    if request.method == "GET" and request.args.get("url"): #Also check if the url exists
        url = request.args.get("url", "")
        if not is_safe_url(url):
            abort(400)  # Abort if the URL is unsafe with client error shown by 400.
        return redirect(url, code=302) #HTTP 302 for temporary redirections.
    if request.method == "POST":
        # CSRF token is automatically validated by Flask-WTF
        feedback = request.form.get("feedback", "")
        if len(feedback) > 1000:  # Prevent excessively large input
            return "Feedback text is too long.", 400 
        dbHandler.insertFeedback(feedback)
        dbHandler.listFeedback()
        return render_template("success.html", state=True, value="Back")
    else:
        dbHandler.listFeedback()
        return render_template("success.html", state=True, value="Back")

@app.route("/signup.html", methods=["POST", "GET"])
@limiter.limit("10 per minute")  # Rate limit to mitigate signup abuse
def signup():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):  # Check if URL is safe
            abort(400) # Abort if the URL is unsafe with client error shown by 400.
        return redirect(url, code=302)
    if request.method == "POST":
        # CSRF token is validated automatically by Flask-WTF.
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        dob = request.form.get("dob", "")
        # Insert user with password hashing in user_management.py
        dbHandler.insertUser(username, password, dob)
        return render_template("index.html")
    else:
        return render_template("signup.html")

@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
@limiter.limit("10 per minute")  # Rate limit login endpoint to prevent brute-force attacks
def home():
    if request.method == "GET" and request.args.get("url"):
        url = request.args.get("url", "")
        if not is_safe_url(url):
            abort(400) # Abort if the URL is unsafe with client error shown by 400.
        return redirect(url, code=302)
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            dbHandler.listFeedback()
            return render_template("success.html", value=username, state=isLoggedIn)
        else:
            return render_template("index.html")
    else:
        return render_template("index.html")

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.logger.setLevel(logging.DEBUG)
    app.run(debug=False, host="0.0.0.0", port=5001) #set debug = True only during testing.

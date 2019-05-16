[![clasp](https://img.shields.io/badge/built%20with-clasp-4285f4.svg)](https://github.com/google/clasp)

# Xero Public App with Google Apps Script

I am trying to connect a Google Sheet to the Xero Public API but I am having trouble figuring out the the HMAC-SHA1 signature. The error that I keep getting is:

`Error starting OAuth flow: oauth_problem=signature_invalid&oauth_problem_advice=Failed%20to%20validate%20signature`

This is coming from the initial request token step. I am basically following along with the standard [OAuth1 library provided by Google](https://github.com/gsuitedevs/apps-script-oauth1).

I found this explanation on the community forums for Xero authentication unfortunately I can't quite figure out where I am going wrong.

From the developer forums:
[https://community.xero.com/developer/discussion/53196360](https://community.xero.com/developer/discussion/53196360)

I'll try breakdown our OAuth 1.0a signing process for public apps .
I'm going to use getting a request token as an example.

The URL for getting a request token is https://api.xero.com/oauth/RequestToken and the method that should be used is POST
If not using a callback URL, wherever mentioned you must use the value oob

1. Create signature base string

The signature base string is created using the request method, request URL, request query parameters, and some extra OAuth parameters.
The extra OAuth parameters are:
oauth_callback, oauth_consumer_key, oauth_nonce, oauth_signature_method, oauth_timestamp, oauth_version

The signature base string is split into 3 parts:
{part 1}&{part 2}&{part 3}

The first part is just the request's HTTP method.
The second part is just the request's URL minus any query parameters, url encoded.

For our example that leaves us with:
POST&https%3A%2F%2Fapi.xero.com%2Foauth%2FRequestToken&{part 3}

Part 3 is created using any provided query string parameters along with the extra OAuth parameters mentioned earlier.
Using all of these parameters, you'll need to build up a list of key, value pairs, separated by ampersands, where the pairs are ordered lexicographically.
Ordered lexicographically basically means the keys are sorted alphabetically uppercase, then lowercase and if any keys are the same they are sorted by value. For example, if our keys were 'apple', 'banana', and 'Banana', they would be ordered 'Banana', 'apple', 'banana'.

For our example, the string would be:
oauth_callback={your callback url}&oauth_consumer_key={your consumer key}&oauth_nonce={a random nonce}&oauth_signature_method=HMAC-SHA1&oauth_timestamp={current timestamp}&oauth_version=1.0

We then need to URL encode this string so that it becomes something like this:
oauth_callback%3D{encoded callback url}%26oauth_consumer_key%3D{your consumer key}%26oauth_nonce%3D{encoded nonce}%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D{current timestamp}%26oauth_version%3D1.0

Using all three parts we now have our signature base string, ready to be signed:
POST&https%3A%2F%2Fapi.xero.com%2Foauth%2FRequestToken&oauth_callback%3D{encoded callback url}%26oauth_consumer_key%3D{your consumer key}%26oauth_nonce%3D{encoded nonce}%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D{current timestamp}%26oauth_version%3D1.0

2. Sign the signature base string

As our example is a public app, we don't have a certificate to sign with and so must build up our own key.
The key is comprised of two parts:
{part 1}&{part 2}

The first part is just your consumer secret, (found in the developer portal along with your consumer key).

The second part is the key of the Request token or Access token you have depending on how far through the 'OAuth flow' you are.

- When acquiring a new Request token, this will be blank.
- When swapping your Request token for an Access token, this will be the Request token key of the request token you just authorised.
- When making API calls with an Access token, this will be the Access token key.

In our example, we are acquiring a new Request token and so part 2 will be left blank.
Our key will be:
{your consumer secret}&

Using this key, you then HMAC-SHA1 sign your signature base string, and then base 64 encode the resulting byte array into a string.
This signature is your oauth_signature used in the next step.

3. Create Authorization header

Using the oauth_signature you just created, and all of the other OAuth parameters mentioned in step 1, you can now create the Authorization header to be appended to your request.

The structure of the Authorization header is as follows (using the same oauth parameter values used in step 1, as they are used to validate your signature):
OAuth oauth_callback="{your callback url}", oauth_consumer_key="{your consumer key}", oauth_nonce="{your random nonce}", oauth_signature="{your oauth_signature}", oauth_signature_method="HMAC-SHA1", oauth_timestamp="{your oauth_timestamp}", oauth_version="1.0"

4. Make the request

Your final request should look something like this

POST https://api.xero.com/oauth/RequestToken HTTP/1.1
Authorization: {Your Authorization header}

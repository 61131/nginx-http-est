# nginx-http-est

Enrollment over Secure Transport (EST) module for Nginx

The Enrollment over Secure Transport (EST) protocol describes a simple, yet functional, certificate management protocol targeting Public Key Infrastructure (PKI) clients that need to acquire client certificates and associated Certification Authority (CA) certificates. This protocol supports both client-generated public/private key pairs and those generated by the CA.

The nginx-http-est module provides EST functionality for a Nginx server.

## Build

To build the nginx-http-est module from the Nginx source directory:

    ./configure --add-module=/path/to/nginx-http-est --with-http_ssl_module
    make
    make install

Note that the nginx-http-est module is dependent upon the HTTP SSL module for normal operations. 

## Configuration

    server {
        ssl_certificate /etc/nginx/ssl/Server.crt;
        ssl_certificate_key /etc/nginx/ssl/Server.key;

        ssl_client_certificate /etc/nginx/ssl/Org-RootCA.crt;
        ssl_verify_client optional;

        listen 443 ssl;
        listen 80 default_server;

        location / {
            ...
        }

        location /.well-known/est {
            est on;
            est_auth_request /auth-backend;
            est_verify_client cert;

            est_root_certificate /etc/nginx/ssl/Org-RootCA.crt;
            est_csr_attrs /etc/nginx/ssl/csrattrs.der;
        }

        location = /auth-backend {
            proxy_pass ...
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }
    }

## Parameters

### est

* **syntax:** `est on|off`
* **default:** `off`
* **context:** `location`

Enable EST operations for HTTP SSL server location. 

The EST server MUST support the path-prefix of "/.well-known/" as defined in [RFC 5785](https://datatracker.ietf.org/doc/html/rfc5785) and the registered name of "est". As such, the default EST server URI path would be "https://www.example.com/.well-known/est". This can be configured through the creation of a location definition for "/.well-known/est" as shown in the example configuration above.

An EST server may also support service for multiple CAs as indicated by an optional additional path segment between the registered application name and the operation path. For example, the following are three example valid URLs for the distribution of CA certificates:

* [https://www.example.com/.well-known/est/cacerts](https://www.example.com/.well-known/est/cacerts)
* [https://www.example.com/.well-known/est/arbitraryLabel1/cacerts](https://www.example.com/.well-known/est/arbitraryLabel1/cacerts)
* [https://www.example.com/.well-known/est/arbitraryLabel2/cacerts](https://www.example.com/.well-known/est/arbitraryLabel2/cacerts)

This configuration can be supported by this module through the inclusion of multiple location directives within the server configuration.

### est_auth_request

* **syntax:** `est_auth_request <uri>`
* **default:** `none`
* **context:** `location`

Sets URI location for HTTP-based client authorization.

The EST server MAY request HTTP-based client authentication. This request can be in addition to successful TLS client authentication if mandated by EST server configuration. Alternatively, HTTP-based client authentication may be used in situations where an EST client did not successfully complete TLS client authentication - This may occur where the EST client is enrolling for the first time or if the certificates available to the EST client cannot be used for TLS client authentication.

This functionality operates in a similar manner to [ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html). If the subrequest returns a 2xx response code, the client is authorized. If the subrequest returns 401 or 403, the client is denied with the corresponding error code. Where this functionality differs from [ngx_http_auth_request_module](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html) is that authentication is only required for selected operation paths as defined in [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030).

This approach permits a range of different authorization mechanisms to be employed in concert with EST server operations.

### est_csr_attrs

* **syntax:** `est_csr_attrs <filename>`
* **default:** `none`
* **context:** `location`

Specifies a file containing certificate attributes that should be provided by clients.

CA policy may allow inclusion of client-provided attributes in certificates that is issues, and some of these attributes may describe information that is not available to the CA.

This parameter specifies a file containing an ASN.1 encoded structure, in Distinguished Encoding Rules (DER) format, that specifies objects and attributes which should be provided by clients. This ASN.1 encoded structure should take the form as described in [RFC 8951](https://datatracker.ietf.org/doc/html/rfc8951):

    CsrAttrs ::= SEQUENCE SIZE (0..Max) OF AttrOrOID
    
    AttrOrOID ::= CHOICE {
      oid        OBJECT IDENTIFIER,
      attribute  Attribute {{AttrSet}} }

    AttrSet ATTRIBUTE ::= { ... }

See OpenSSL [asn1parse](https://www.openssl.org/docs/man1.1.1/man1/openssl-asn1parse.html) for details on how to create this ASN.1 specification.

This information will be used both in the validation of CSRs received from clients and when responding to requests for CSR attributes (using an operation path of "/csrattrs") required by the EST server. The EST server does not require client authentication or authorization to respond to requests for CSR attributes.

### est_root_certificate

* **syntax:** `est_root_certificate <filename>`
* **default:** `none`
* **context:** `location`

Configures the trust anchor certificate to be used for EST operations.

This directive specifies the certificate - in PEM format - to be returned to EST clients to bootstrap the trust anchor between client and server. EST clients may request this trust anchor certificate information with a HTTPS GET message using an operation path of "/cacerts". The EST server will not require client authentication or authorization to reply to this request.

### est_verify_client

* **syntax:** `est_verify_client none|auth|cert|both`
* **default:** `cert`
* **context:** `location`

Configures the mechanism to be used for verifying EST clients. 

The EST server may authorize clients based upon either TLS certificate validation as per [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) and/or HTTP-based authentication. 

If TLS certificate validation is configured, the client certificate is verified as per the operation of the `ssl_client_certificate` and `ssl_verify_client` HTTP SSL directives. It is important to note that as not all EST operations require authorization, the `ssl_verify_client` directive for the HTTP server MUST be set to `optional`.

For HTTP-based authentication, the `est_auth_request` directive must be set with the URI location against which subrquests are issued to determine whether the given client is authorized.

## References

* [RFC 7030 Enrollment over Secure Transport](https://datatracker.ietf.org/doc/html/rfc7030)
* [RFC 8951 Clarification of Enrollment over Secure Transport (EST): Transfer Encodings and ASN.1](https://datatracker.ietf.org/doc/html/rfc8951)


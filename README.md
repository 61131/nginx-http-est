# nginx-http-est

Enrollment over Secure Transport (EST) module for Nginx

The Enrollment over Secure Transport (EST) protocol describes a simple, yet functional, certificate management protocol targeting Public Key Infrastructure (PKI) clients that need to acquire client certificates and associated Certification Authority (CA) certificates. This protocol supports both client-generated public/private key pairs and those generated by the CA.

The nginx-http-est module provides EST functionality for a Nginx server. 

## Features

* Distribution of CA certificates
* Client certificate request functions
* ~~Full Certificate Management over CMS (CMC)~~ (Not implemented)
* Server-side key generation
* CSR attributes
* TLS certificate and HTTP-based authentication
* Proof-of-possession (POP) validation

## Build

To build the nginx-http-est module from the Nginx source directory:

    ./configure --add-module=/path/to/nginx-http-est --with-http_ssl_module
    make
    make install

Note that the nginx-http-est module is dependent upon the HTTP SSL module for normal operations. If the HTTP SSL module is not included within the nginx server configuration, client TLS certificate authentication and proof-of-possession (POP) functionality will not be available.

## Configuration

    server {
        ssl_certificate /etc/nginx/ssl/Server.crt;
        ssl_certificate_key /etc/nginx/ssl/Server.key;

        ssl_client_certificate /etc/nginx/ssl/Org-RootCA.crt;
        ssl_verify_client optional;

        listen 443 ssl;
        listen 80 default_server;

        location / { ... }

        location /.well-known/est {
            est on;
            est_auth_request /auth-backend;
            est_csr_attrs /etc/nginx/ssl/csrattrs.der;
            est_pop on;
            est_root_certificate /etc/nginx/ssl/Org-RootCA.crt;
            est_verify_client cert;

            est_ca_root_certificate /etc/nginx/ssl/Org-RootCA.crt;
            est_ca_private_key /etc/nginx/ssl/Org-RootCA.key;
            est_ca_serial_number /etc/nginx/ssl/Org-RootCA.srl;
            est_ca_validity_days 30;
        }

        location = /auth-backend {
            proxy_pass ...
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }
    }

## Parameters

The configuration directives and parameters associated with this module may broadly be divided into those which specify EST server behaviour and those which specify behaviour of the underlying CA.

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

### est_ca_private_key

* **syntax:** `est_ca_private_key <filename>`
* **default:** `none`
* **context:** `location`

Configures the private key to be used in association with the CA root certificate.

This directive specifies the private key to be employed in association with the certificate authority trust anchor for signing operations. This private key should be stripped of any passphrase such that this private key can be opened without user intervention for automated signing operations.

### est_ca_root_certificate

* **syntax:** `est_ca_root_certificate <filename>`
* **default:** `none`
* **context:** `location`

Configures the CA root certificate to be used for signing client certificates.

This directive specifies the certificate - in PEM format - to be used for signing certificates created for EST clients. This certificate may be the same as that distributed as a trust anchor for EST server operations (see est_root_certificate directive).

### est_ca_serial_number

* **syntax:** `est_ca_serial_number <filename>`
* **default:** `none`
* **content:** `location`

Configures the path where the CA sequential certificate serial number is stored.

This directive specifies the file location where the last, sequential certificate serial number issued by the CA is stored. Each certificate issued by the CA will be provided with a unique certificate serial number. If this file does not exist, a random number is generated as a starting point for new certificate serial number. 

If this directive is not specified, a filename for serial number storage will be created based upon that for the CA root certificate.

### est_ca_validity_days

* **syntax:** `est_ca_validity_days <days>`
* **default:** `30`
* **context:** `location`

Configures the default validity interval - in days - for newly signed certificates.

This directive specifies the length of time, in days following creation date, that certificates generated by the certificate authority will be valid. 

### est_csr_attrs

* **syntax:** `est_csr_attrs <filename>`
* **default:** `none`
* **context:** `location`

Specifies a file containing certificate attributes that should be provided by clients.

CA policy may allow inclusion of client-provided attributes in certificates that is issues, and some of these attributes may describe information that is not available to the CA. Examples may include the Media Access Control (MAC) address of the client device or the intended application use of the certificate.

This parameter specifies a file containing an ASN.1 encoded structure, in Distinguished Encoding Rules (DER) format, that specifies objects and attributes which should be provided by clients. This ASN.1 encoded structure should take the form as described in [RFC 8951](https://datatracker.ietf.org/doc/html/rfc8951):

    CsrAttrs ::= SEQUENCE SIZE (0..Max) OF AttrOrOID
    
    AttrOrOID ::= CHOICE {
      oid        OBJECT IDENTIFIER,
      attribute  Attribute {{AttrSet}} }

    AttrSet ATTRIBUTE ::= { ... }

See OpenSSL [asn1parse](https://www.openssl.org/docs/man1.1.1/man1/openssl-asn1parse.html) for details on how to create this ASN.1 specification. 

For example, the following asn1.cnf file describes the requirement for a MAC address to be included in the CSR attributes. The corresponding attributes definition file is created using the `openssl asn1parse` command.

    ~ # cat asn1.cnf
    asn1=SEQUENCE:AttrOrOID

    [AttrOrOID]
    field1 = OID:1.3.6.1.1.1.1.22   # macAddress

    ~ # openssl asn1parse -genconf asn1.cnf -noout -out csrattrs.der
    ~ # openssl asn1parse -in csrattrs.der -inform der
        0:d=0  hl=2 l=   9 cons: SEQUENCE
        2:d=1  hl=2 l=   7 prim: OBJECT            :1.3.6.1.1.1.1.22

This information will be used both in the validation of CSRs received from clients and when responding to requests for CSR attributes (using an operation path of "/csrattrs") required by the EST server. The EST server does not require client authentication or authorization to respond to requests for CSR attributes.

### est_http

* **syntax:** `est_http on|off|limit`
* **default:** `off`
* **content:** `location`

Permits HTTP requests to be used for EST operations.

When enabled, this option allows the EST server to receive and process requests over both TLS-secured HTTP (HTTPS) and unsecured HTTP. While [RFC 7030](https://datatracker.ietf.org/doc/html/rfc7030) only describes the use of a TLS-secured HTTP session for EST operations, the use of unsecured HTTP may be useful where a device lacks bootstrap client TLS certificates. This mode of operations is also useful to provide visibility of EST operations for development and debugging purposes.

It is important to note that EST operations dependent upon TLS will be non-operational where these are performed over unsecured HTTP - These operations include certificate-based authentication and client demonstration of the proof-of-possession (POP) of the private key associated with a certificate signing request (CSR).

Where the value of `limit` is employed for this configuration parameter, access via unsecured HTTP will be restricted to only those end-points not requiring client verification ("/cacerts" and "/csrattrs").

### est_pop

* **syntax:** `est_pop on|off`
* **default:** `off`
* **content:** `location`

Requires client demonstrate proof-of-possession (POP) of the private key associated with the certificate signing request (CSR).

This directive requires that all clients demonstrate the proof-of-possession (POP) of the private key associated with a certificate signing request (CSR) and that the client was able to sign the CSR after the TLS session was established. This demonstration requires the client to include the tls-unique value from the TLS subsystem as described in [RFC 5929](https://datatracker.ietf.org/doc/html/rfc5929) as an attribute within the CSR.

Where enabled, this directive requires the client to include the tls-unique value as a base64 encoded string in the certification request challenge-password field. If this attribute is missing or mismatched with that on the server, the certificate generation request will fail.

### est_root_certificate

* **syntax:** `est_root_certificate <filename>`
* **default:** `none`
* **content:** `location`

Configures the certificate authority trust anchor to be used for EST operations.

This directive specifies the certificate - in PEM format - to be returned to EST clients to bootstrap the trust anchor between client and server. EST clients may request this trust anchor certificate information with a HTTPS GET message using an operation path of "/cacerts". The EST server will not require client authentication or authorization to reply to this request.

### est_verify_client

* **syntax:** `est_verify_client none|auth|cert|both`
* **default:** `cert`
* **context:** `location`

Configures the mechanism to be used for verifying EST clients. 

The EST server may authorize clients based upon either TLS certificate validation as per [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) and/or HTTP-based authentication. 

If TLS certificate validation is configured, the client certificate is verified as per the operation of the `ssl_client_certificate` and `ssl_verify_client` HTTP SSL directives. It is important to note that as not all EST operations require authorization, the `ssl_verify_client` directive for the HTTP server MUST be set to `optional`.

For HTTP-based authentication, the `est_auth_request` directive must be set with the URI location against which subrquests are issued to determine whether the given client is authorized.

## Limitations

The following limitations are noted with respect to this EST server implementation:

* The EST server does not support Transport Layer Security Secure Remote Password (TLS-SRP) for certificate-less TLS mutual authentication. 
* The EST server does not support the additional symmetric or asymmetric encryption of the server-generated private key with encryption outside of that provided by the TLS transport.
* The EST server does not (yet) validate Subject field and SubjectAltName extension within certificate signing requests submitted for re-enrollment. This is primarily due to the limited meta-data persistence associated with certificate generation and renewal.

## References

* [RFC 7030 Enrollment over Secure Transport](https://datatracker.ietf.org/doc/html/rfc7030)
* [RFC 7894 Alternative Challenge Password Attributes for Enrollment over Secure Transport](https://datatracker.ietf.org/doc/html/rfc7894)
* [RFC 8295 EST (Enrollment over Secure Transport) Extensions](https://datatracker.ietf.org/doc/html/rfc8295)
* [RFC 8951 Clarification of Enrollment over Secure Transport (EST): Transfer Encodings and ASN.1](https://datatracker.ietf.org/doc/html/rfc8951)
* [RFC 1341 MIME (Multipurpose Internet Mail Extensions): Mechanisms for Specifying and Describing the Format of Internet Message Bodies](https://datatracker.ietf.org/doc/html/rfc1341)


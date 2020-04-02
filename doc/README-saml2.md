Using SAML2 with ocserv
========================

For saml support the [lasso3 library](https://lasso.entrouvert.org/)
is required. The minimum requirement is version 2.2.0. Further dependencies
are [apache portable runtime library (apr1)](https://apr.apache.org)
and [glib2.0](https://developer.gnome.org/glib/).

ocserv uses a configuration file to setup the SAML2 configuration.
The important options for ocserv usage are the following:
```
sp-metadata-file = /etc/spmetadata.xml
sp-keyfile = /etc/letsencrypt/live/exampledomain.com/privkey.pem
sp-cert = /etc/letsencrypt/live/exampledomain.com/fullchain.pem
idp-metadata-file = /etc/idpmeta.xml
idp-cert = /etc/idp-cert.pem
```

sp-metadata-file specifies the SAML sp role parameters, in this case
ocserv. Use doc/sample.sp-metadata.xml and substitute your hostname
over 'example.com'. The URIs are hard coded and mimic the SAML
implementation of Anyconnect.

sp-keyfile and sp-cert specify ocserv's private key and certificate,
respectively. This is for signing of SAML messages.

idp-metadata-file is your SAML idP's metadata xml file. Your identity
provider should provide you with this.

idp-cert is your SAML idP's certificate, used for signing SAML
messages. Again, your identity provider will supply this.

Ocserv configuration
====================

For authentication the following line should be enabled.
```
auth = "saml[config=/etc/saml/sso.conf]"
```

config is the path to the configuration file documented above.

SAML logout requests are currently not implemented.
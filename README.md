# nginx-autogen
An nginx module that auto-generates SSL certificates and signs with a given CA root. Build as usual:
<pre>
   ./configure --with-openssl=DIR ...
</pre>
In nginx.conf, set the paths to the root CA certificate and key:
<pre>
server {
        listen       443 ssl;
        server_name  test-server.com;

        ssl_certificate      /path/to/rootCA.crt;
        ssl_certificate_key  /path/to/rootCA.key;

        ssl_autogen on;
        ssl_generated_cert_path /var/autogen;
        ssl_autogen_subject "/CN=test-server.com/OU=AutogenSSL/O=AutogenSSL/C=RU/E=dmitry.negoda@gmail.com";
...
}
</pre>
The <code>ssl_generated_cert_path</code> option specifies the path where to cache the certificates.


# cozycerts
OpenSSL wrapped so dummies like me can use it lazily.
A self contained CA intended to work across linux environments.

git pull in whatever directory you want cozycerts.
/opt/cozycerts, /home/$user/cozycerts, /etc/cozycerts, wherever you want.

Root CA tab:
- On first startup, create your Root CA.
- View and manage your inventory of certs signed by the CA.
- DANGER ZONE: Resets CA to factory settings. Useful for lab environments.

Certs tab:
- Upload CSR to sign, self explanitory.
- Generate new cert, using service/host.domain.name, & IP. 
  - Creates key pair, CSR, and cert when self signed.
  - Can also toggle for generating ONLY CSR's. 

Settings tab:
- Edit cert metadata. Will probably rename to 'Metadata'

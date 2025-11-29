# cozycerts
OpenSSL wrapped in streamlit so dummies like me can use it lazily.  
A self contained CA intended to work in a venv environments.  

git clone in whatever directory you want cozycerts to live.  
/opt/cozycerts, /home/$user/cozycerts, /etc/cozycerts, wherever.  

```bash
git clone https://github.com/cozywho/cozycerts.git
cd cozycerts
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run main.py
```

Root CA tab:
- On first startup, create your Root CA.
- View and manage your inventory of certs signed by the CA.
- DANGER ZONE: Resets CA to factory settings. Useful for lab environments.

Certs tab:
- Generate new cert, using service/host.domain.name, & IP. 
  - Creates key pair, CSR, and cert when self signed.
  - Can also toggle for generating keypairs and CSR's for other CA's.
- Upload CSR to sign by Root CA, self explanitory.

Metadata tab:
- Edit cert metadata.

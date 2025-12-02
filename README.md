# cozycerts
OpenSSL wrapped in streamlit so dummies like me can use it lazily.  
A self contained CA intended to work in a venv.

git clone in whatever directory you want cozycerts to live.  
/opt/cozycerts, /home/$user/cozycerts, /etc/cozycerts, wherever.  

```bash
git clone https://github.com/cozywho/cozycerts.git
cd cozycerts
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run main.py
```

Root CA tab:
- On first startup, create your Root CA.
- View and manage your inventory of certs signed by the CA.
- Select entries, then use buttons for downloading, revoking, deleting, and converting.

Generate tab:
- Generate new certs.
  - Creates key pair, CSR, and cert when self signed.
  - Can also toggle for generating keypairs and CSR's for other CA's.
- Upload CSR to sign by Root CA, self explanitory.

Metadata tab:
- Edit cert metadata.

Inspect tab:
- Allows for certificate inspection.

Reset tab:
- Factory reset your CA. Comment out the code if in production.

-----------------------

Plans:
Trust chain / SubCA.


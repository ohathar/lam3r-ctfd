# lam3r-ctfd
for all your mobile CTF desires!

```
virtualenv -p python3 lam3r-ctfd
cd lam3r-ctfd
. bin/activate
git clone https://github.com/ohathar/lam3r-ctfd
cd lam3r-ctfd
pip install -r requirements.txt
cp app.example.db app.db
./app.py
```

or install nginx/apache and proxy pass your way to victory!
```
apt install nginx letsencrypt
letsencrypt certonly --standalone -d mysite.biz
cp lam3r.conf /etc/nginx/sites-available/
## edit to suit ##
ln -s /etc/nginx/sites-available/lam3r.conf /etc/nginx/sites-enabled/
systemctl restart nginx
```

Run lam3r-ctfd as a systemd service
```
cp lam3r.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable lam3r # start at boot
systemctl start lam3r
```


# wake
A Flask web app to turn on your computer using wake on lan

# Apache
On Ubuntu or Debain you will want to install the following:
* apt-get install apache2
* apt-get install libapache2-mod-wsgi-py3

You will want to create an apache conf file for wake under ```/etc/apache2/sites-available``` and name it ```wake.conf```


copy and paste the following and under server name you will want to change it



```
<VirtualHost *:80>
        ServerName change me
        WSGIScriptAlias / /var/www/html/wake/wake.wsgi
        <Directory /var/www/html/wake/>
            Require all granted
        </Directory>
        Alias /static /var/www/html/wake/static
        <Directory /var/www/html/wake/static/>
            Require all granted
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

You will want to clone this repository next

* git clone https://github.com/L1ghtn1ng/wake.git /var/www/html/

# Dependencies
* Python 3.11+
* Flask
* Wakeonlan
* PyYAML

This project uses [uv](https://docs.astral.sh/uv/) for dependency management. To install uv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then install the project dependencies:

```bash
uv sync
```

To run the application in development mode:

```bash
uv run python wake.py
```

# Adding your computers
Add your computers/servers to computers.yaml like the following;
```yaml
demo1:
  mac: 30:5a:3a:56:57:58
  ip: 10.0.0.2
demo2:
  mac: e0:d4:e8:98:42:11
  ip: 10.0.0.254
```

# Final Prep
You are now ready to enable the wake.conf file under ```/etc/apache2/sites-available```

* a2ensite wake

Now go to the servers IP address and you should have wake up and running

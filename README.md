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
            Order allow,deny
            Allow from all
        </Directory>
        Alias /static /var/www/html/wake/static
        <Directory /var/www/html/wake/static/>
            Order allow,deny
            Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

You will want to clone this repository next

* git clone https://github.com/L1ghtn1ng/wake.git /var/www/html/

You will want to under the wake directory open wake.wsgi that I have provided and change the secrect key. It says change me, after doing so save and exit
the file

# Dependencies
* Python3
* Flask
* Wakeonlan
* Pyyaml

To install these you will need to install pip3 which you can do by ```apt-get install python3-pip```
Then you will want to run

* sudo pip3 install flask
* sudo pip3 install wakeonlan
* sudo pip3 install Pyyaml

Or run ``sudo pip3 -r requirements.txt``

# Adding your computers
Add your computers/servers to computers.yaml like the following;
```yaml
demo1: 30:5a:3a:56:57:58
demo2: 28:c2:dd:g5:b3:e3
```

# Final Prep
You are now ready to enable the wake.conf file under ```/etc/apache2/sites-available```

* a2ensite wake

Now go to the servers IP address and you should have wake up and running

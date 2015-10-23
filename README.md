# wake
A Flask web app to turn on your computer using wake on lan

# Apache
On Ubuntu or Debain you will want to install the following:
* apt-get install apache2
* apt-get install libapache2-mod-wsgi-py3

You will want to create an apache conf file for wake under ```/etc/apache2/sites-available``` and name it ```wake.conf```


copy and paste the following and under server name you will want to change it



```<VirtualHost *:80>
        ServerName change me
        WSGIScriptAlias / /var/www/wol/wake.wsgi
        <Directory /var/www/wol/>
            Order allow,deny
            Allow from all
        </Directory>
        Alias /static /var/www/wol/static
        <Directory /var/www/wol/static/>
            Order allow,deny
            Allow from all
        </Directory>
        ErrorLog ${APACHE_LOG_DIR}/error.log
        LogLevel warn
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
```

You will want to clone this repository next

* git clone https://github.com/L1ghtn1ng/wake.git wol
* sudo cp -R wol/ /var/www/

You will want to under the wol directory open wake.wsgi that I have provided and change the secrect key. It says change me, after doing so save and exit
the file

# Dependencies
* Python3
* Flask
* Wakeonlan

To install these you will need to install pip3 which you can do by ```apt-get install python3-pip```
Then you will want to run

* sudo pip3 install flask
* sudo pip3 install wakeonlan

# Adding your computers
Under wol directory under templates, you will want to modify index.html
On line 29 you will want to change ``html<option value="mac addr here in capitals">PC name</option>`` and if you want to add more computers
just copy and paste that line. Once done save and exit the file

# Final Prep
You are now ready to enable the wake.conf file under ```/etc/apache2/sites-available```

* a2ensite wake

Now go to the servers IP address and you should have wake up and running

NFC RFID Linux PAM
=============

Thid PAM module uses D-Logic RFID SDK binary

Steps to use this module:
- Go to MyAuthGen
- Compile it using "make" command.
- Power on D-Logic reader and put a blank RFID card on it.
- Get root access (su)
- Run MyAuthGen as root with a 32-byte key as parameter, you can try to generate 32byte random string from http://strongpasswordgenerator.com/
- So commandline will be: ./MyAuthGen r6B4915kO41G0603DL4H91s116b8LE5T

Above steps, will encrypt a fixed string using given key, store it in system and write the key in RFID card.

Now go to PAM folder.
- Compile it using "make" command.
- Then install it using "make install". This should put NFCMyAuth.so into /lib/security
- Now edit PAM file you can to use NFCMyAuth and add "auth required NFCMyAuth.so"
In my case, I use it in my Debian system with GDM desktop environment, so I have "auth required NFCMyAuth.so" in my /etc/pam.d/gdm-password

Now if you logout and try to login, even if you enter correct username/password, if you don't put RFID card on top of reader, you shouldn't be able to login.

For more info: http://www.codeandsec.com/Linux-RFID-Pluggable-Authentication-Modules

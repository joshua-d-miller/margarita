Margarita - Python 3 (Now with SAML Authentication)
===================================================

Margarita is a web interface to [reposado](http://github.com/wdas/reposado) the Apple Software Update replication and catalog management tool. While the reposado command line administration tools work great for folks who are comfortable in that environment something a little more accesible might be desired.

Margarita attempts to be an easy to use and quick interface to list or delist update products in branch catalogs per the usual reposado catalog management concepts.

This fork of margarita now has SAML authentication using the [python3-saml](https://github.com/onelogin/python3-saml) plugin.

I have also performed some minor updates to the CSS of this project to give it a hopefully cleaner look. You can always remove the CSS if you'd like.

![Screenshot](https://github.com/joshua-d-miller/margarita/blob/master/static/Margarita%20Interface.png)

Requirements
------------

**Python 3**

You will need to use Python 3 with this version of Margarita. From there I highly recommend creating a **virtualenv** to store margarita in.

**reposado (Python 3)**

See the [reposado](https://github.com/wdas/reposado/tree/py3compatibility) project for how to install and configure it. It needs to be setup and configured with at least Apple's software update catalogs initially synced.

__Note__: Reposado may be installed either via setup.py/setuptools or simply run from the code files (either by downloading and extracting the files or by cloning the repository, etc.). Running from the code files is the documented way to run reposado. It is important to know in which way reposado is installed as Margarita needs to reference the location of the reposado library files which are located wherever reposado is installed. See below on installation for details on setup. Thanks to [timsutton](https://github.com/timsutton) on [issue #1](https://github.com/jessepeterson/margarita/issues/1) for clarifying this.

**Flask**

    easy_install flask

Or

    pip install flask

If you prefer to install into a Python [virtualenv](http://www.virtualenv.org/) that works as well.

**Python 3 SAML**

This margarita install uses python3-saml so you will need to create a saml folder in your margarita folder. From there you will need to contact your IDP and build the files *settings.json* and *advanced_settings.json*. You can also use a *certs* folder if you'd like or you can put the certificate itself in the *settings.json* file. See below for examples:

    [settings.json](https://github.com/onelogin/python3-saml/blob/master/demo-flask/saml/settings.json)
    [advanced_settings.json](https://github.com/onelogin/python3-saml/blob/master/demo-flask/saml/advanced_settings.json)

Installation (Tested on CentOS 8)
---------------------------------

1. Create a virtualenv in a directory of your choice.
2. Change directory into this location.
3. Activate the virtualenv
4. Clone the repository into your newly created virtualenv
5. Perform installation of the required packages by using pip.

    pip install -r requirements.txt

6. Configure you secret key for use with SAML by copying the *secret_key.py* or creating a *secret_key.py* file and creating your own unique SECRET_KEY that ca be used when initiating SAML.
5. If reposado is running from code per the documented installation instructions (and not installed into site-packages via easy_install/setup.py) then one needs to create a symlink to the reposadolib directory in order for Margarita to find the reposado common libraries.
6. Create a symlink to the reposado configuration file. This is needed because the reposado libraries reference the config file from the executing script's directory. In Margarita's case this is Margarita's source directory.

Create symlinks:

    cd /path/to/margarita-install

    # may be optional depending on reposado installation
    ln -s /path/to/reposado-git-clone/code/reposadolib .

    ln -s /path/to/reposado-git-clone/code/preferences.plist .


Creating a service in Linux
---------------------------

To create a service on linux you can basically copy paste this and modify it to the directory that your margarita environment lives.

    [Unit]
    Description=Margarita

    [Service]
    WorkingDirectory=/where/your/margarita/install/lives/margarita_env
    ExecStart=/where/your/margarita/install/lives/margarita_env/bin/python /usr/local/where/your/margarita/install/lives/margarita_env/margarita.py
    Restart=always

    StandardOutput=syslog
    StandardError=syslog

    [Install]
    WantedBy=multi-user.target

**Note:** Margarita must have permission to the reposado repository in order to effect any changes. This may mean you need to run margarita as a different user:

    sudo -u _www python margarita.py


Other web servers
-----------------

In the documentation above Margarita runs in the "development" web server built into Flask. This may not be ideal in some situations and there are some alternatives for running in a more "production"-ready webservers. Joe Wollard has an excellent article describing how to setup Margarita using mod_wsgi on Linux using WSGI:

- [Running Margarita in Apache](http://denisonmac.wordpress.com/2013/02/28/running-margarita-in-apache)

Setting up on Linux
-------------------

Helpful guides written by others:

- [Setting up Reposado and Margarita on Linux – Part 1](http://macadmincorner.com/setting-up-reposado-and-margarita-on-linux-part-1/)
- [Install Reposado with Margarita on CentOS / Red Hat Enterprise Linux](http://www.adminsys.ch/2012/09/23/install-reposado-margarita-centos-red-hat-enterprise-linux/)

# websql
WebSQL - A simple multi database supported SQL console in your web browser

Installation Instructions

1) Install dependancies:

  # install from OS packages
  sudo yum install perl-CGI perl-CGI-Session perl-DBI perl-URI

  # or install the following using CPAN
  # CGI CGI::Session DBI URI::Escape

2) Copy websql directory into your htdocs folder

  cp config.pl.sample config.pl

3) Create some database connections in config.pl

4) Create some users
   execute from command line 
   perl index.pl

5) Point web browser to https://yourserver/websql

6) You may need to add the following apache config:
   <Directory /path/to/your/htdocs/websql>
     AllowOverride All
     Order Deny,Allow
     Deny from all
     Allow from all
   </Directory>

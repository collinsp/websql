#!/usr/bin/perl

use strict;

# load runtime config
use FindBin qw($Bin);
require "$Bin/../conf/config.pl";

{ print "Add User\n";
  my ($user, $pass);
  while(! $user) {
    print "username: ";
    $_=<STDIN>; chomp; $user=$_ if /^\S+$/;
  }

  system("stty -echo");
  while ($pass eq '') {
    while(! $pass) {
      print "password: ";
      $_=<STDIN>; chomp; $pass=$_ if /^\S+$/;
    }
    my $pass2;
    while(! $pass2) {
      print "\nrepeat password: ";
      $_=<STDIN>; chomp; $pass2=$_ if /^\S+$/;
    }
    if ($pass ne $pass2) {
      print "\nPasswords do not match. Try again.\n";
      $pass='';
    }
  }
  system("stty echo");
  my $salt = join('',('.','/',0 .. 9,'A'..'Z','a'..'z')[rand 64, rand 64]);
  my $hash = crypt($pass, $salt);
  print "
Add the following line to %WEBSQL::USERS in file conf/config.pl
Make sure you remove connections the user should not have access too.

  '$user' => {
    crypthash => '$hash',
    connections => [".join(',', map { "'$_'" } sort keys %WEBSQL::CONNECTIONS)."]
  },\n\n";
  exit(0);
}

1;

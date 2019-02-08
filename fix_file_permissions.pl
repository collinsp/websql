#!/usr/bin/perl

use strict;
use FindBin qw($Bin);

my $USER = $ENV{OSUSER}   || $ENV{USER};
my $GROUP = $ENV{OSGROUP} || 'apache';

sub run {
  my @cmd = @_;
  print join(' ', @cmd)."\n";
  my $rv = system(@cmd);
  if ($rv) {
    print STDERR "ERROR: exit code: $rv in fix_file_permissions.pl for cmd: ".join(' ', @cmd)."\n";
    exit(-1);
  }

  return undef;
}


die "must be root\n" unless $>==0;
chdir $Bin or die "could not chdir $Bin; $!\n";

my $webcontent = ".htaccess blank.html favicon.ico index.pl instructions.html main.css";
my $webscripts = "index.pl config.pl";

run("chown -R $USER.$GROUP .");
run("chmod -R u=rwX,go= .");
run("chmod g=rx .");
run("chmod u=rw,g=r,o= $webcontent");
run("chmod u=rwx,g=rx,o= $webscripts");

# if SELinux is enabled, assign proper file contexts
if (`sestatus` =~ /SELinux status\:\s+enabled/s) {
  run('chcon -R system_u:object_r:root_t:s0 .');
  run("chcon system_u:object_r:httpd_sys_content_t:s0 $webcontent");
  run("chcon system_u:object_r:httpd_sys_script_exec_t:s0 $webscripts");
}



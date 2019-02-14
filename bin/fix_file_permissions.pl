#!/usr/bin/perl

use strict;
use FindBin qw($Bin);

my $USER = $ENV{OSUSER}   || 'root';
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

# change directory to project root
chdir "$Bin/../" or die "could not chdir $Bin; $!\n";

die "could not find file: conf/config.pl; you can create it from the sample at conf/config.conf.sample\n" unless -f "conf/config.pl";

run("chown -R $USER.$GROUP .");
run("chmod -R u=rwX,go= .");
run("chmod ug=rX .");
run("chmod -R g=rX htdocs cgi-bin");
run("chmod ug=rx cgi-bin/*.pl");
run("chmod u=rwx bin/*.pl");
run("chmod g=rx conf conf/config.pl");

# if SELinux is enabled, assign proper file contexts
if (`sestatus` =~ /SELinux status\:\s+enabled/s) {
  run('chcon -R system_u:object_r:root_t:s0 .');
  run('chcon -R system_u:object_r:bin_t:s0 bin');
  run("chcon -R system_u:object_r:httpd_sys_content_t:s0 conf htdocs");
  run("chcon -R system_u:object_r:httpd_sys_script_exec_t:s0 cgi-bin");
  run('chcon -R system_u:object_r:httpd_config_t:s0 conf/apache');
  run('chcon -R system_u:object_r:httpd_log_t:s0 logs');
}


#!/usr/bin/perl
package WEBSQL;

use strict;
use DBI();
use CGI();
use CGI::Session();
use URI::Escape();
use MIME::Base64;

# package globals reset for each request
our ($q, $dbh, $session, %USERS, %CONNECTIONS);

# load runtime config
use FindBin qw($Bin);
require "$Bin/config.pl";

# if not running in CGI mode, do interactive shell
if (! $ENV{HTTP_HOST}) {
  print "Add User\n";
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
  print "\n\nAdd the following line to %USERS

  '$user' => {
    crypthash => '$hash',
    connections => [".join(',', map { "'$_'" } sort keys %CONNECTIONS)."]
  },\n\n";
  exit(0);
}



# database drivers to add limit/offset to sql
# sql is an array ref where elem 0 is sql, and other elems are binds
# the driver should modify the passed in $sql array ref
our %SQL_LIMIT_DRIVER;
$SQL_LIMIT_DRIVER{Oracle} = sub {
  my ($sql, $limit, $offset) = @_;
  $$sql[0] = "SELECT * FROM ($$sql[0]) WHERE rownum <= ?";
  push @$sql, $limit;
};
$SQL_LIMIT_DRIVER{default} = sub {
  my ($sql, $limit, $offset) = @_;
  $$sql[0] .= " LIMIT ? OFFSET ?";
  push @$sql, $limit, $offset;
};

# database drivers to produce a dictionary
our %SQL_DICTIONARY_DRIVER;
$SQL_DICTIONARY_DRIVER{Oracle} = sub {
  my ($connection) = @_;
  my $buf;
  local $$dbh{LongReadLen} = 9999999;
  my $x = $dbh->selectall_arrayref("
    SELECT TABLE_TYPE, TABLE_NAME
    FROM cat
    WHERE TABLE_NAME NOT LIKE 'BIN\$%'
    AND TABLE_TYPE IN ('TABLE','SEQUENCE')
    ORDER BY 2,1");
  my $sth = $dbh->prepare("SELECT dbms_metadata.get_ddl(?, ?) FROM dual");
  foreach my $typenames(@$x) {
    ($_) = $dbh->selectrow_array($sth, undef, @$typenames);
    s/\bUSING\ INDEX\b\s*//gs;
    s/\s+\).*/  \)/s; # rm table options
    s/\ \ STORAGE\([^\)]+\)//gs;
    s/\ \ TABLESPACE\ \"[^\"]+\"\s+ENABLE//gs;
    s/^\ \ USING\ INDEX\ .+$//m;
    s/^\ \ PCTFREE\ .+$//gm;
    s/\s+ENABLE\s*\)/\)/sg;
    s/\s+ENABLE\,\s*$/\,/gm;
    s/\n\s*\n/\n/g;
    s/\n\s*\,\s*\n/\,\n/g;
    s/\n\   \(/\(\n/s;
    $buf .= $_."\n";
  }
  $buf =~ s/^\ \ //mg; # remove extra spaces
  return $buf;
};

$SQL_DICTIONARY_DRIVER{mysql} = sub {
  my ($connection) = @_;
  my $buf;
  my @cmd = ('mysqldump');
  my $c = $CONNECTIONS{$connection} or return undef;
  push @cmd, ("-u", $$c{user});
  push @cmd, ("-p". $$c{pass}); # yes the . is intentional
  push @cmd, ("--compact","--no-set-names","--skip-opt","--no-data");
  if ($$c{dsn} =~ /\:(\w+)$/) {
    push @cmd, $1;
  } elsif ($$c{dsn} =~ /database\=(\w+)/) {
    push @cmd, $1;
  } else {
    die "couldn't parse database name in $$c{dsn}\n";
  }
  open(my $fh, '-|', @cmd) or die "Problem executing cmd: ".join(' ', @cmd)."\nERROR: $!\n";
  my $tablename;
  my $colname;
  while (<$fh>) {
    next if /\ SET\ /;
    if (/^CREATE\ TABLE\ ([\w\']+)/) {
      $tablename = $1;
    } elsif (/^\ \ (\`[^\`]+\`)/) {
      $colname = $1;
    }
    $buf .= $_;
  }
  return $buf;
};





################################################
# utils
################################################

sub escape_html { CGI::escapeHTML(@_); }
sub escape_uri { URI::Escape::uri_escape(@_); }

# force scalar param return
sub param { return scalar($q->param(@_)); }

# generate cross site request forgery for input token
sub csrf_token {
  my @readonly = @_;
  die "missing session id\n" unless $session->id;
  die "missing remote addr\n" unless $q->remote_addr;
  my $data = join('~', $session->id, map { param($_) } @readonly, $q->remote_addr());
  my $salt = join('',('.','/',0 .. 9,'A'..'Z','a'..'z')[rand 64, rand 64]);
  my $token = crypt($data, $salt);
  return "<input type=hidden name=csrf value='".escape_html($token)."'>";
}

# verify csrf token. will die if invalid.
sub csrf_check {
  my @readonly = @_;
  die "missing session id\n" unless $session->id;
  die "missing remote addr\n" unless $q->remote_addr;
  my $data = join('~', $session->id, map { param($_) } @readonly, $q->remote_addr());
  my $token0 = param('csrf') || die "missing csrf param\n";
  my $token1 = crypt($data, $token0);
  die "bad csfr\n" unless $token0 eq $token1;
}

# return an http header
sub http_header {
  my %opts = @_;
  $opts{-x_frame_options} ||= 'SAMEORIGIN';
  $opts{-Cache_Control} ||= 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0';
  return CGI::header(%opts);
}

# push a notification html msg into the user session
sub push_notify {
  my ($msg) = @_;
  $session->param('msg', $session->param('msg').$msg);
}

# pop all notifications from the user session
sub pop_notify {
  my $msg = $session->param('msg');
  $session->clear('msg');
  return $msg; 
}

# redirect to url
sub redirect {
  my ($url) = @_;
  print CGI::redirect(-uri => $url, -status => 303);
  return undef;
}

# connect to database
sub dbh {
  my $c = $CONNECTIONS{param('connection')} or return undef;
  my $dbh = DBI->connect($$c{dsn}, $$c{user}, $$c{pass},
      { PrintError => 0, RaiseError => 1 }) or die "Could not connect to db. $DBI::errstr\n";
  $$dbh{LongReadLen} = 99999;
  $$dbh{LongTruncOk} = 1;
  if ($$dbh{Driver}{Name} =~ /Oracle/i) {
    $dbh->do("ALTER SESSION SET NLS_DATE_FORMAT='YYYY-MM-DD HH24:MI:SS'");
  }
  my $sql;
  eval {
    foreach $sql (parse_sql_buffer($$c{initsql})) {
      $dbh->do($sql);
    }
  };
  if ($@) {
    die "initsql error: $@";   
  }
  return $dbh;
}

sub extract_hilight {
  my ($sql) = @_;
  $sql =~ s/\r\n/\n/gs;
  my $selStart = int(param('selStart')) || 0;
  my $selEnd = int(param('selEnd')) || length($sql);
  $sql = substr($sql, $selStart, $selEnd - $selStart) if $selStart < $selEnd;
  return $sql; 
}

# parse the sql buffer. returns array of sql statements to execute.
sub parse_sql_buffer {
  my ($sql) = @_;
  $sql =~ s/\r\n/\n/gs;

  # strip comments
  $sql =~ s/\-\-.*$//mg;
  $sql =~ s/\/\/.*$//mg;
  $sql =~ s/\/*.*?\*\///sg;

  # parse for multiple statements (delimited by ;)
  my @rv;
  my $i=0;
  my $l = length($sql);
  my $in_quote = 0;
  my $buf;
  while ($i < $l) {
    my $ch = substr($sql, $i, 1);
    $in_quote ^= 1 if $ch eq "'";
    if (! $in_quote && $ch eq ';') {
      push @rv, $buf;
      $buf = '';
    } else {
      $buf .= $ch;
    }
    ++$i;
  }
  push @rv, $buf;
  @rv = grep { s/^\s*//s; s/\s*$//s; $_; } @rv;
  return @rv;
}

# return a full date
sub ymdhms {
  my @d = localtime;
  return
    sprintf("%04d", $d[5] + 1900).
    sprintf("%02d", $d[4] + 1).
    sprintf("%02d",$d[3]).
    sprintf("%02d",$d[2]).
    sprintf("%02d",$d[1]).
    sprintf("%02d",$d[0]);
}


################################################
# page content actions (must have act_ prefix)
################################################

my $frameBuster = '<script>if(top!=self)top.location.href=self.location.href;</script>';

my $faviconLink = '<link rel="shortcut icon" href="favicon.ico?v=2">';
my $cssLink = '<link rel=stylesheet href="main.css?v=1">';

# the login form
sub act_loginform {

  # get notifications first in case session is deleted
  my $notifications = pop_notify();

  # prevent session reuse - if current session is used, recreate it
  if ($session->param('user') ne '' || $session->is_expired()) {
    $session->delete();
    $session->flush();
    $session = CGI::Session->new();
  }

  # create secure session cookie that is only exposed to this path and not accessible to scripts
  my $cookie = new CGI::Cookie(
    -name     => $session->name,
    -value    => $session->id,
    -path     => $q->url(-absolute=>1),
    -httponly => 1,
    -secure   => ($q->url() =~ /^https/) ? 1 : 0
  );
  
  print http_header(-cookie => $cookie),
"<html>
<head>
$frameBuster
$faviconLink
$cssLink
</head>
<body>
<h1 align=center>WebSQL Login</h1>
$notifications
<form method=post class=msgbox style='width:300px;'>
".csrf_token().'
<p><label>username<br>'.$q->textfield(-name => 'user', -autofocus=>1).'</label>
<p><label>password<br>'.$q->password_field('pass').'</label>
<p align=center>
<button type=submit name=act value=login class=bigger>login</button>
</form>
</body>
</html>';
}

# handle login
sub act_login {
  csrf_check();
  my $user = param('user');
  my $pass = param('pass');
  my $h = $USERS{$user}{crypthash};
  if ($h && crypt($pass,$h) eq $h) {
    $session->param('user', $user); 
    redirect($q->url());
  } else {
    push_notify('<div class=msgbox>Invalid username or password</div>');
    redirect('?act=loginform');
  }
}

# load the main frame, called after successful login
sub act_loadframeset {
  print http_header(),
"<html>
<head>
$frameBuster
$faviconLink
<title>WebSQL</title>
</head>
<frameset rows='*,300'>
  <frame name=results src='instructions.html'>
  <frameset cols='60%,40%'>
    <frame name=codeeditor src='?act=codewindow'>
    <frame name=dictionary src='?act=dictionary'>
  </frameset>
</frameset>
</html>";
}

# display database dictionary
sub act_dictionary {
  my $buf;

  if (param('connection') ne '') {
    if (ref($CONNECTIONS{param('connection')}{dictionary}) eq 'CODE') {
      $buf = $CONNECTIONS{param('connection')}{dictionary}->();
    } elsif ($dbh && $SQL_DICTIONARY_DRIVER{$$dbh{Driver}{Name}}) {
      $buf = $SQL_DICTIONARY_DRIVER{$$dbh{Driver}{Name}}->(param('connection'));
    } else {
      $buf = "database ".escape_html($$dbh{Driver}{Name})." not supported";
    }
    $buf = "<pre style='height:100%;overflow-y:auto;overflow-x:hidden;'>".escape_html($buf)."</pre>";
  } else {
    $buf = "<p style='color:#888;position:absolute;bottom:40%;width:100%;text-align:center;'>Select a database dictionary to display."; 
  }
  print http_header(),
"<html>
<head>$cssLink</head>
<body>
$buf
<form>
<div class=cmdbar style='width:13em;'>
".$q->popup_menu(-name => 'connection', -values => $USERS{$session->param('user')}{connections})."
<button type=submit name=act value=dictionary>&#9658;</button>
</div>
</form>
<a style='position:absolute;top:0;right:20px;' href='?act=loginform' target=_top class=button>logout</a>
</body>
</html>";
}

# execute SQL queries
sub act_execute {
  csrf_check();
  $session->param('sql_buffer', param('sql'));
  $session->param('last_connection', param('connection'));
  act_execute_format_html();
}

# load the coding frame
sub act_codewindow {
  param('connection', $session->param('last_connection')) unless param('connection');
  print http_header(),"
<html>
<head>
$cssLink
</head>
<body>
<form target=results method=post>
".csrf_token()."
  <input type=hidden name=selStart>
  <input type=hidden name=selEnd>
  <textarea autofocus name=sql id=sqleditor>".escape_html($session->param('sql_buffer'))."</textarea>
  <div class=cmdbar>
    ".$q->popup_menu(-name => 'connection', -values => $USERS{$session->param('user')}{connections})."
    <label style='margin-left:6px;'>limit ".$q->popup_menu(-name => 'limit', -values => [(25,100,500,2000,5000,10000)])."</label>
    <button style='margin-left:6px;' type=submit name=act value=execute id=executebut title='hotkey: [Shift-Enter]'>&#9658;</button>
  </div>
</form>
<script>
var f = document.forms[0];
// remember if shift is pressed
var SHIFT=0;
document.onkeydown = function(evt) {
  var x = (evt.which) ? evt.which : evt.keyCode
  if (x==16) SHIFT=1;
  else if (SHIFT && x==13) {
    document.getElementById('executebut').click();
    evt.preventDefault();
  }
};
document.onkeyup = function(evt) {
  var x = (evt.which) ? evt.which : evt.keyCode
  if (x==16) SHIFT=0;
};
f.onsubmit = function(){
  f.selStart.value = f.sql.selectionStart;
  f.selEnd.value   = f.sql.selectionEnd;
};
</script>
</body>
</html>";
}

# load previous page in query
sub act_execute_format_html_prev {
  my $limit = int(param('limit')) || 1000;
  my $offset = int(param('offset')) || 0;
  $offset -= $limit;
  $offset = 0 if $offset < 0;
  param('offset', $offset);
  act_execute_format_html();
}

# load next page in query
sub act_execute_format_html_next {
  my $limit = int(param('limit')) || 1000;
  my $offset = int(param('offset')) || 0;
  $offset += $limit;
  param('offset', $offset);
  act_execute_format_html();
}

# execute queries and display results as html
sub act_execute_format_html {
  csrf_check();
  my @sql_queries = parse_sql_buffer(extract_hilight(param('sql')));
  my $buf;
  my $token = csrf_token();
  my $last_sql;
  eval {
    $dbh->begin_work();
    foreach my $sql (@sql_queries) {
      $last_sql = $sql;
      my @sql = ($sql);
      my $limit = int(param('limit')) || 1000;
      my $offset = int(param('offset')) || 0;
      if ($sql[0] =~ /^\s*select/is) {
        my $limit_driver = $SQL_LIMIT_DRIVER{$$dbh{Driver}{Name}} || $SQL_LIMIT_DRIVER{default};
        $limit_driver->(\@sql, $limit + 1, $offset);
        my ($sql, @binds) = @sql;
        my $sth = $dbh->prepare($sql);
        $sth->execute(@binds);
        my $nameAr = $sth->{NAME};
        $buf .= "<form method=post>$token".$q->hidden('limit',$limit).$q->hidden('offset',$offset).$q->hidden('connection');
        $buf .= "<table><thead><tr><th class=rownum></th>"
          .join('', map { "<th title='".escape_html($_)."'>".escape_html($_)."</th>" } @{ $sth->{NAME} })
          ."</tr></thead><tbody>";
        my $rownum=0;
        while (my $x = $sth->fetchrow_arrayref()) {
          $rownum++;
          last if $rownum > $limit;
          $buf .= "<tr><td class=rownum>".($rownum + $offset)."</td>".join('', map { "<td>".escape_html($_)."</td>" } @$x)."</tr>";
        }
        $sth->finish();
        $buf .= "</tbody></table>";

        $buf .= "<div class=outputcmdbar>
<label>SQL: <textarea name=sql readonly>".escape_html($last_sql)."</textarea></label>
<button type=submit name=act value=execute_format_csv>csv</button>
</div>";
        $buf .= "<button type=submit name=act value=execute_format_html_prev class=bigger";
        $buf .= " disabled" unless $offset > 0;
        $buf .= ">&#9664; prev</button>";
        $buf .= "<button type=submit name=act value=execute_format_html_next class=bigger";
        $buf .= " disabled" unless $rownum > $limit;
        $buf .= ">next &#9654;</button>";
      }
      else {
        my $rv = $dbh->do($sql[0]);
        $buf .= "<pre>".escape_html($last_sql)."\n$rv rows affected</pre>";
      }
    }
    $buf .= "</form>";
    $dbh->commit();
  };

  if ($@) {
    $dbh->rollback();
    my $err = $@;
    $err =~ s/\ at\ .*?\ line\ \d+\.$//;
    $buf = "<pre class=resulterrblock><div class=resultsql><strong>SQL:</strong>\n".escape_html($last_sql)."</div>\n<div class=resulterrmsg><strong>ERROR:</strong>\n".escape_html($err)."</div></pre>";
  }
  print http_header(), "<html><head>$cssLink</head><body>$buf</body></html>";
}

# execute single query and display results as csv
sub act_execute_format_csv {
  csrf_check();
  my $buf;
  my $sql = param('sql');
  eval {
    my $sth = $dbh->prepare($sql);
    $sth->execute();
    my $nameAr = $sth->{NAME};
    $buf .= join(',', map { s/\"/""/g; '"'.$_.'"' } @$nameAr);
    while (my $x = $sth->fetchrow_arrayref()) {
      $buf .= "\n".join(',', map { s/\"/""/g; '"'.$_.'"' } @$x);
    }
    print http_header(-type => 'text/csv', -attachment => ymdhms().'.csv'), $buf;
  };
  if ($@) {
    print http_header(-type => 'text/plain'), "Error: $@\n\nSQL:\n$sql";
  }
}

################################################
# main routine
################################################
sub handler {
  local ($q, $dbh, $session);
  $q = new CGI();
  $session = new CGI::Session();
  $dbh = dbh();

  # make sure user is using login actions if not logged in
  param('act', 'loginform') if param('act') !~ /^(login|css)$/ && ! $USERS{$ENV{REMOTE_USER}} && ! $USERS{$session->param('user')};

  (__PACKAGE__->can('act_'.param('act')) || \&act_loadframeset)->();
  $session->flush() if $session;
  $dbh->disconnect() if $dbh;
}
handler() unless caller;
1;

#! /usr/bin/perl

use DBI;
use POSIX;
#use strict;

sub dsn    { return "DBI:mysql:flow:localhost"; }
sub user   { return "stat"; }
sub passwd { return "my_password"; }

my($dbh, $table, $msg, $stamp);

sub startwrite
{
	unless ($dbh = DBI->connect(dsn, user, passwd, { PrintError => 1 }))
	{
		die "Can't connect to MySQL server: $DBI::err ($DBI::errstr)\n";
	}
	$table = strftime("flow_%Y_%m", localtime());
	$stamp = strftime("%Y%m%d%H%M%S", localtime());
	unless ($dbh->do("CREATE TABLE IF NOT EXISTS $table (
		date TIMESTAMP NOT NULL,
		user VARCHAR(20),
		bytes_in  BIGINT UNSIGNED NOT NULL,
		bytes_out BIGINT UNSIGNED NOT NULL,
		INDEX (user),         UNIQUE (date, user)
	)")) {
		$msg="Can't create table $table: $DBI::err ($DBI::errstr)";
		$dbh->disconnect();
		die "$msg\n";
	}
}

sub stopwrite
{
	$dbh->disconnect();
	undef($dbh);
}

sub writestat
{
# $user, $bytes_in, $bytes_out
	die "Not connected\n" unless $dbh;
	unless($dbh->do("INSERT IGNORE $table VALUES($stamp, '$user', $bytes_in, $bytes_out)")) {
		$msg="Can't insert to $table: $DBI::err ($DBI::errstr)";
		$dbh->disconnect();
		die "$msg\n";
	}
}

sub recv_pkt
{
# $router, $srcip, $dstip, $direction, $nexthop, $len, $pkts, $input, $output,
# $src_as, $dst_as, $proto, $src_port, $dst_port, $src_class, $dst_class
# Any of this variables can be changed
# Return link name or empty string
	return '';
}

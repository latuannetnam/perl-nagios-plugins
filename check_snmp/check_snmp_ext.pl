#!/usr/bin/perl
#
#    check_snmp_ext nagios plugin: Monitor SNMP OID value
#    Copyright (C) 2019 Le Anh Tuan (tuan.la@netnam.vn/latuannetnam@gmail.com)
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

use strict;
use warnings;
use 5.008;
use Nagios::Monitoring::Plugin;
use Net::SNMP;
use Data::Dumper;
use Net::Ping;

my $STATEDIR = '/var/tmp';

#----------------------------------------
# Main program 
#----------------------------------------
my $np = Nagios::Monitoring::Plugin->new(
	shortname => 'SNMP-EXT',
	usage => "usage: check_snmp_ext.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'SNMP-EXT',
	version => '1.0'
);


#----------------------------------------
# Option Parsing
#----------------------------------------

$np->add_arg(
	spec => 'hostname|H=s',
	help => "-H, --hostname=<host_address>\n   Hostname to check",
	required => 1,
	default => 'localhost',
);

$np->add_arg(
	spec => 'port|p=s',
	help => "-p, --port=<snmp_port>\n   SNMP port (default: 161)",
	default => 161,
);

# IPv4/IPv6

$np->add_arg(
	spec => 'ipv4|4',
	help => "-4\n   use IPv4 (default)",
);

$np->add_arg(
	spec => 'ipv6|6',
	help => "-6\n   use IPv6",
);

# SNMPv1/2

$np->add_arg(
	spec => 'protocol|P=s',
	help => "-P, --protocol=[1|2|3]\n   SNMP protocol version ('2c' also accepted)",
	required => 1,
	default => '2c',
);

$np->add_arg(
	spec => 'community|C=s',
	help => "-C, --community=<snmp_community>\n   SNMP community (SNMP version 1 or 2 only)",
	required => 1,
	default => 'public',
);

# SNMPv3

$np->add_arg(
	spec => 'username=s',
	help => "--username=<snmp_username>\n   SNMP username (SNMP version 3)",
);

$np->add_arg(
	spec => 'authkey=s',
	help => "--authkey=<snmp_authkey>\n   SNMP authkey (SNMP version 3)",
);

$np->add_arg(
	spec => 'authpassword=s',
	help => "--authpassord=<snmp_authpassword>\n   SNMP authpassword (SNMP version 3)",
);

$np->add_arg(
	spec => 'authprotocol=s',
	help => "--authprotocol=<snmp_authprotocol>\n   SNMP authprotocol (SNMP version 3)",
);

$np->add_arg(
	spec => 'privkey=s',
	help => "--privkey=<snmp_privkey>\n   SNMP privkey (SNMP version 3)",
);

$np->add_arg(
	spec => 'privpassword=s',
	help => "--privpassword=<snmp_privpassword>\n   SNMP privpassword (SNMP version 3)",
	default => undef
);

$np->add_arg(
	spec => 'privprotocol=s',
	help => "--privprotocol=<snmp_privprotocol>\n   SNMP privprotocol (SNMP version 3)",
);

# other

$np->add_arg(
	spec => 'noperfdata|F',
	help => "-F, --noperfdata\n   Don't output performance data",
);


$np->add_arg(
	spec => 'datadir|d=s',
	help => "-d <directory>, --datadir=<directory>\n   Data directory for persistent performance data (default: $STATEDIR)",
	required => 1,
	default => $STATEDIR
);

$np->add_arg(
	spec => 'timeout|t=i',
	help => "Seconds before connection times out (default: 10)",
    default => 10
);

$np->add_arg(
	spec => 'oid|o=s',
	help => "Object identifier(s) or SNMP variables whose value you wish to query",
);

$np->add_arg(
	spec => 'label|l=s',
	help => "Label for output from plugin",
);

# Threshold
$np->add_arg(
	spec => 'warning|w=s',
	help => "INTEGER:INTEGER\n   warning threshold\n"
);

$np->add_arg(
	spec => 'critical|c=s',
	help => "INTEGER:INTEGER\n   critical threshold\n"
);

$np->getopts();

# Safety Net
alarm $np->opts->timeout;

#----------------------------------------
# IP Transport Domain
#----------------------------------------

my $domain = 'udp4';

if (defined $np->opts->ipv6)
{
	if (defined $np->opts->ipv4)
	{
		$np->nagios_die('options -4 and -6 are mutually exclusive');
	}
	$domain = 'udp6';
}

#----------------------------------------
# SNMP Session
#----------------------------------------


my ($snmp_session, $snmp_error);

if ($np->opts->protocol eq '1'
	|| $np->opts->protocol eq '2'
	|| $np->opts->protocol eq '2c')
{
	($snmp_session, $snmp_error) = Net::SNMP->session(
		-hostname => $np->opts->hostname,
		-port => $np->opts->port,
		-domain => $domain,
		-version => ($np->opts->protocol eq '2c' ? '2' : $np->opts->protocol),
		-community => $np->opts->community,
		-translate => [-octetstring => 0x0],
	);
}
elsif ($np->opts->protocol eq '3')
{
	($snmp_session, $snmp_error) = Net::SNMP->session(
		-hostname => $np->opts->hostname,
		-port => $np->opts->port,
		-domain => $domain,
		-version => $np->opts->protocol,
		-username => $np->opts->username,
		-authkey => $np->opts->authkey,
		-authpassword => $np->opts->authpassword,
		-authprotocol => $np->opts->authprotocol,
		-privkey => $np->opts->privkey,
		-privpassword => $np->opts->privpassword,
		-privprotocol => $np->opts->privprotocol,
		-translate => [-octetstring => 0x0],
	);
}
else
{
	$np->nagios_die("invalid snmp protocol");
}

$np->nagios_die($snmp_error) if (!defined $snmp_session);



#----------------------------------------
# GetRequest
#----------------------------------------
my $oid = $np->opts->oid;
my $result = $snmp_session->get_request(-varbindlist => [$oid]);
$np->nagios_die('check_snmp_ext: ' . $snmp_session->error()) if (!defined $result);
$snmp_session->close();

# print("$oid:$result->{$oid}");
#----------------------------------------
# Performance Data
#----------------------------------------
my $label = $oid;
my $data = $result->{$oid};
if (defined($np->opts->label))
{
	$label = $np->opts->label;
}
$np->add_perfdata(label => $label, value => $data, warning => $np->opts->warning, critical => $np->opts->critical);

#----------------------------------------
# Metrics Summary
#----------------------------------------

my $metrics = "";
#----------------------------------------
# Status Checks
#----------------------------------------

my $code;
my $prefix = " ";
$np->add_message(OK, "$data");
if (($code = $np->check_threshold(check => $data, warning => $np->opts->warning, critical => $np->opts->critical)) != OK)
{
	$np->add_message($code, ' ');
}
my ($exit_code, $exit_message) = $np->check_messages();

$exit_message = $prefix . join(' ', ($exit_message, $metrics));
$exit_message =~ s/^ *//;

$np->nagios_exit($exit_code, $exit_message);
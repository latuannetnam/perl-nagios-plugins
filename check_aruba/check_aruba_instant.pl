#!/usr/bin/perl
#
#    check_aruba_instant nagios plugin: Monitor Aurba Instant Virtual Controller and APs
#    Copyright (C) 2019 Le Anh Tuan (tuan.la@netnam.vn/latuannetnam@gmail.com)
#
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

my $STATEDIR = '/var/tmp';

my $OIDS_SYSTEM = {
	 sysDescr => '.1.3.6.1.2.1.1.1.0',
	 sysObjectID => '.1.3.6.1.2.1.1.2.0',
	 sysName => '.1.3.6.1.2.1.1.5.0',
};
my $OIDS_VC = {
	 aiVirtualControllerName => '.1.3.6.1.4.1.14823.2.3.3.1.1.2.0',
	 aiVirtualControllerVersion => '.1.3.6.1.4.1.14823.2.3.3.1.1.4.0', 
};

my $OIDS_AP = {
	aiAPName => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.2',
	aiAPIPAddress => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.3',
	aiAPModel => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.5',
	aiAPModelName => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.6',
	aiAPCPUUtilization => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.7',
	aiAPMemoryFree => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.8',
	aiAPTotalMemory => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.10',
	aiAPStatus => '.1.3.6.1.4.1.14823.2.3.3.1.2.1.1.11',
}

#----------------------------------------
# Sub/functions
#----------------------------------------
sub sanitize_fname($)
{
	my $name = shift;
	$name =~ s/[^0-9a-z_-]/_/gi;
	return $name;
}

sub get_vc($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	# Get VC general information
	my $oids = $OIDS_SYSTEM;
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	my $result = $snmp_session->get_request(-varbindlist => [@oids_list]);
	$snmp_session->close();
	$np->nagios_die($snmp_session->error()) if (!defined $result);

	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $metrics = sprintf("%s [%s]",
				$result->{$oids->{sysName}},
				$result->{$oids->{sysDescr}},
	);
	#----------------------------------------
	# Threshold Checks
	#----------------------------------------
	my $code;

	my $prefix = " ";

	$np->add_message(OK,'');
	my ($exit_code, $exit_message) = $np->check_messages();

	$exit_message = $prefix . join(' ', ($exit_message, $metrics));
	$exit_message =~ s/^ *//;

	$np->nagios_exit($exit_code, $exit_message);

	

}

#----------------------------------------
# Main program 
#----------------------------------------
my $np = Nagios::Monitoring::Plugin->new(
	shortname => 'ARUBA-INSTANT',
	usage => "usage: check_aruba_instant.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'ARUBA-INSTANT',
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
	default => 2,
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
	spec => 'warnifcritical',
	help => "--warnifcritical\n   Returns a WARNING instead of CRITICAL on interface status (default: no)",
);

$np->add_arg(
	spec => 'datadir|d=s',
	help => "-d <directory>, --datadir=<directory>\n   Data directory for persistent performance data (default: $STATEDIR)",
	required => 1,
	default => $STATEDIR
);

# modes
# modes
$np->add_arg(
	spec => 'modes',
	help => "--modes\n   List check modes.",
);

$np->add_arg(
	spec => 'mode|m=s',
	help => "-m, --mode\n   Check modes.",
	required => 1,
	default => 'vc',
);

# Threshold
$np->add_arg(
	spec => 'powerdelta=f',
	help => "max_power=PwrHiAlarm - powerdelta\n min_power=PwrLowAlarm + powerdelta\n",
);

$np->add_arg(
	spec => 'currentdelta=f',
	help => "max_current=CurrentHiAlarm - currentdelta\n min_current=CurrentLowAlarm + currentdelta\n",
);

$np->add_arg(
	spec => 'tempdelta=f',
	help => "max_temperature=tempHiAlarm - tempdelta\n min_current=tempLowAlarm + tempdelta\n",
);
$np->getopts();

# Safety Net
alarm $np->opts->timeout;

#----------------------------------------
# List mode
#----------------------------------------
if (defined $np->opts->modes)
{
	print "Mode list:\n";
	print "vc: check Virtual Controller state \n";
	print "ap: check Access Point state \n";
	$np->nagios_exit(OK,'');
}


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
	);
}
else
{
	$np->nagios_die("invalid snmp protocol");
}

$np->nagios_die($snmp_error) if (!defined $snmp_session);


#----------------------------------------
# Cache Directory
#----------------------------------------

if (! -w $np->opts->datadir)
{
	$np->nagios_die("Unable to write to data directory" . $np->opts->datadir);
}

#----------------------------------------
# Virtual Controller mode
#----------------------------------------
if ($np->opts->mode eq "vc")
{
	get_vc($np, $snmp_session);
}
elsif ($np->opts->mode eq "ap")
{

}

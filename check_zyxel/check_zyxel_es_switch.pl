#!/usr/bin/perl
#
#    check_zyxel_switch nagios plugin: Monitor Cisco Wireless controller
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
use Net::SNMP qw(:snmp);
use Data::Dumper;
use Net::Ping;
use Storable;

my $STATEDIR = '/var/tmp';
my $OIDS_MEMORY = {
   sysMemoryPoolName => '.1.3.6.1.4.1.890.1.5.8.57.124.1.1.2',
   sysMemoryPoolUsed => '.1.3.6.1.4.1.890.1.5.8.57.124.1.1.4',
   sysMemoryPoolUtil => '.1.3.6.1.4.1.890.1.5.8.57.124.1.1.5',
   sysMemoryPoolTotal => '.1.3.6.1.4.1.890.1.5.8.57.124.1.1.3',
};

my $OIDS_TEMPERATURE = {
   tempCurValue => '.1.3.6.1.4.1.890.1.5.8.57.9.2.1.2',
   tempHighThresh => '.1.3.6.1.4.1.890.1.5.8.57.9.2.1.5',
};

my $OIDS_POWER = {
   voltageCurValue => '.1.3.6.1.4.1.890.1.5.8.57.9.3.1.2',
   voltageLowThresh => '.1.3.6.1.4.1.890.1.5.8.57.9.3.1.6',
   voltageNominalValue => '.1.3.6.1.4.1.890.1.5.8.57.9.3.1.5',
};

#----------------------------------------
# Sub/functions
#----------------------------------------
sub get_index_from_oid($)
{
	my $oid = shift or die;
	my ($index) = $oid =~ /(\.[^.]+)$/;
	$index = substr($index, 1);
	return $index;
}

sub get_memory($$) {
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_MEMORY;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}

	my $result = $snmp_session->get_entries(-columns => [@oids_list], -maxrepetitions => 10);
	$np->nagios_die("get_memory:" . $snmp_session->error()) if (!defined $result);
	$snmp_session->close();
	my $memory_pool = {};
	my $memory_avg = 0;
	foreach my $oid (keys %$result) {
		# print("$oid: " . $result->{$oid} . "\n");
		my $index =get_index_from_oid($oid);
		my $memory_info = $memory_pool->{$index};
		if (!defined $memory_info) {
			$memory_info = {};
		}
		if (oid_base_match($OIDS_MEMORY->{sysMemoryPoolName}, $oid)) {
			# print("pool name:" . $result->{$oid} . "\n");
			$memory_info->{'name'}  = $result->{$oid};
		}
		elsif (oid_base_match($OIDS_MEMORY->{sysMemoryPoolUsed}, $oid)) {
			# print("memory used:" . $result->{$oid} . "\n");
			$memory_info->{'value'}  = $result->{$oid};
		}
		elsif (oid_base_match($OIDS_MEMORY->{sysMemoryPoolUtil}, $oid)) {
			# print("memory used:" . $result->{$oid} . "\n");
			$memory_info->{'percent'}  = $result->{$oid};
			$memory_avg += $result->{$oid};
		}
		elsif (oid_base_match($OIDS_MEMORY->{sysMemoryPoolTotal}, $oid)) {
			# print("memory total:" . $result->{$oid} . "\n");
			$memory_info->{'max'}  = $result->{$oid};
		}
		$memory_pool->{$index} = $memory_info;
	}
	# print(Data::Dumper->new([$memory_pool])->Terse(1)->Purity(1)->Useqq(1)->Dump());
	my $size = keys %$memory_pool;
	$memory_avg = int($memory_avg/$size);
	#----------------------------------------
    # Metrics Summary
    #----------------------------------------
    my $metrics = "avg memory used  $memory_avg%";
    my $code;
    my $prefix = "";
	$np->add_message(OK,'');
	
	foreach my $index (keys %$memory_pool)
	{
		#----------------------------------------
		# Perf data
		#----------------------------------------
		my $memory_info = $memory_pool->{$index};
		if (!$np->opts->noperfdata)
		{
			$np->add_perfdata(label => "memory_" . $memory_info->{'name'}, 
							  value => $memory_info->{'value'},
							  max => $memory_info->{'max'},
				 			  warning => $np->opts->w_memory, 
							  critical => $np->opts->c_memory);
		}
		#----------------------------------------
		# Status Checks
		#----------------------------------------
		if (($code = $np->check_threshold(check => $memory_info->{'percent'}, 
				warning => $np->opts->w_memory, 
				critical => $np->opts->c_memory)) != OK)
		{
			$np->add_message($code, " [" . $memory_info->{'name'} . "] ");
		}
	}

	my ($exit_code, $exit_message) = $np->check_messages();
    $exit_message = $prefix . join(' ', ($exit_message, $metrics));
    $exit_message =~ s/^ *//;
    $np->nagios_exit($exit_code, $exit_message);
}

sub get_temperature($$) {
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_TEMPERATURE;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	my $result = $snmp_session->get_entries(-columns => [@oids_list], -maxrepetitions => 10);
	$np->nagios_die("get_temperature:" . $snmp_session->error()) if (!defined $result);
	$snmp_session->close();
	my $temperature_pool = {};
	my $temperature_avg = 0;
	foreach my $oid (keys %$result) {
		my $index =get_index_from_oid($oid);
		# print("$index: " . $result->{$oid} . "\n");
		my $temperature_info = $temperature_pool->{$index};
		if (!defined $temperature_info) {
			$temperature_info = {};
		}
		
		if (oid_base_match($OIDS_TEMPERATURE->{tempCurValue}, $oid)) {
			$temperature_info->{'value'}  = $result->{$oid};
		}
		elsif (oid_base_match($OIDS_TEMPERATURE->{tempHighThresh}, $oid)) {
			# print("temperature total:" . $result->{$oid} . "\n");
			$temperature_info->{'max'}  = $result->{$oid};
		}
		$temperature_pool->{$index} = $temperature_info;
	}
	# print(Data::Dumper->new([$temperature_pool])->Terse(1)->Purity(1)->Useqq(1)->Dump());
	
	#----------------------------------------
    # Metrics Summary
    #----------------------------------------
    my $metrics = "";
    my $code;
    my $prefix = "";
	$np->add_message(OK,'');
	
	foreach my $index (sort keys %$temperature_pool)
	{
		#----------------------------------------
		# Perf data
		#----------------------------------------
		my $temperature_info = $temperature_pool->{$index};
		if (!$np->opts->noperfdata)
		{
			$np->add_perfdata(label => "temp_" . $index, 
							  value => $temperature_info->{'value'},
							  max => $temperature_info->{'max'},
							  critical => $temperature_info->{'max'});
		}
		#----------------------------------------
		# Status Checks
		#----------------------------------------
		if (($code = $np->check_threshold(check => $temperature_info->{'value'}, 
				critical => $temperature_info->{'max'})) != OK)
		{
			$np->add_message($code, " [temp_" . $index . "] ");
		}
	}

	my ($exit_code, $exit_message) = $np->check_messages();
    $exit_message = $prefix . join(' ', ($exit_message, $metrics));
    $exit_message =~ s/^ *//;
    $np->nagios_exit($exit_code, $exit_message);
}

sub get_power($$) {
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_POWER;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	my $result = $snmp_session->get_entries(-columns => [@oids_list], -maxrepetitions => 10);
	$np->nagios_die("get_power:" . $snmp_session->error()) if (!defined $result);
	$snmp_session->close();
	my $power_pool = {};
	my $power_avg = 0;
	foreach my $oid (keys %$result) {
		my $index =get_index_from_oid($oid);
		# print("$index: " . $result->{$oid} . "\n");
		my $power_info = $power_pool->{$index};
		if (!defined $power_info) {
			$power_info = {};
		}
		
		if (oid_base_match($OIDS_POWER->{voltageCurValue}, $oid)) {
			$power_info->{'value'}  = $result->{$oid}/1000;
		}
		elsif (oid_base_match($OIDS_POWER->{voltageLowThresh}, $oid)) {
			# print("power total:" . $result->{$oid} . "\n");
			$power_info->{'min'}  = $result->{$oid}/1000;
		}
		$power_pool->{$index} = $power_info;
	}
	# print(Data::Dumper->new([$power_pool])->Terse(1)->Purity(1)->Useqq(1)->Dump());
	
	#----------------------------------------
    # Metrics Summary
    #----------------------------------------
    my $metrics = "";
    my $code;
    my $prefix = "";
	$np->add_message(OK,'');
	
	foreach my $index (sort keys %$power_pool)
	{
		#----------------------------------------
		# Perf data
		#----------------------------------------
		my $power_info = $power_pool->{$index};
		if (!$np->opts->noperfdata)
		{
			$np->add_perfdata(label => "voltage_" . $index, 
							  value => $power_info->{'value'},
							  max => $power_info->{'min'},
							  critical => $power_info->{'min'} . ":"
							  );
		}
		#----------------------------------------
		# Status Checks
		#----------------------------------------
		if (($code = $np->check_threshold(check => $power_info->{'value'}, 
				critical => $power_info->{'min'} . ":")) != OK)
		{
			$np->add_message($code, " [voltage_" . $index . "] ");
		}
	}

	my ($exit_code, $exit_message) = $np->check_messages();
    $exit_message = $prefix . join(' ', ($exit_message, $metrics));
    $exit_message =~ s/^ *//;
    $np->nagios_exit($exit_code, $exit_message);
}

#----------------------------------------
# Main program 
#----------------------------------------
my $np = Nagios::Monitoring::Plugin->new(
	shortname => 'Zyxel',
	usage => "usage: check_juniper_qos.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'Zyxel',
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

$np->add_arg(
	spec => 'nonblocking',
	help => "Non-blocking mode",
	
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

# modes
$np->add_arg(
	spec => 'modes',
	help => "--modes\n   List check modes.",
);

$np->add_arg(
	spec => 'mode|m=s',
	help => "-m, --mode\n   Check modes.",
	required => 1,
	default => 'memory',
);

#Thresholds
$np->add_arg(
	spec => 'w_memory=s',
	help => "INTEGER:INTEGER\n   warning threshold for memory\n"
);

$np->add_arg(
	spec => 'c_memory=s',
	help => "INTEGER:INTEGER\n   critical threshold for memory\n"
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
my $nonblocking = 0;
if (defined $np->opts->nonblocking)
{ 
	$nonblocking = 1;
}

my ($snmp_session, $snmp_error);

if ($np->opts->protocol eq '1'
	|| $np->opts->protocol eq '2'
	|| $np->opts->protocol eq '2c')
{
	($snmp_session, $snmp_error) = Net::SNMP->session(
		-hostname => $np->opts->hostname,
		-port => $np->opts->port,
		-nonblocking  => $nonblocking,
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
# List mode
#----------------------------------------
if (defined $np->opts->modes)
{
	print "Mode list:\n";
	print "memory: get memory \n";
    print "temperature: get temperature \n";
    print "power: get power voltage\n";
	$np->nagios_exit(OK,'');
}


#----------------------------------------
# Plugin mode
#----------------------------------------
if ($np->opts->mode eq "memory")
{
	get_memory($np, $snmp_session);
}
elsif ($np->opts->mode eq "temperature")
{
	get_temperature($np, $snmp_session);
}
elsif ($np->opts->mode eq "power")
{
	get_power($np, $snmp_session);
}
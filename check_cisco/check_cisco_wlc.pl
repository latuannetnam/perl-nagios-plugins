#!/usr/bin/perl
#
#    check_cisco_wlc nagios plugin: Monitor Cisco Wireless controller
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

my $STATEDIR = '/var/tmp';
my $MAX_ENTRIES = 10;
my $CACHE_EXPIRED = 6 * 60; # cache expired time in seconds

my $OIDS_SYSTEM = {
	 sysDescr => '.1.3.6.1.2.1.1.1.0',
	 sysObjectID => '.1.3.6.1.2.1.1.2.0',
	 sysName => '.1.3.6.1.2.1.1.5.0',
};

my $OIDS_WLC = {
	sysName => '.1.3.6.1.2.1.1.5.0',
	#  agentInventoryGroup
	# agentInventoryMachineModel => '.1.3.6.1.4.1.14179.1.1.1.3.0',
	# clsSysInfo
	# clsSysApConnectCount => '.1.3.6.1.4.1.9.9.618.1.8.4.0',
	# clsCurrentOnlineUsersCount => '.1.3.6.1.4.1.9.9.618.1.8.15.0',
	clsSysCurrentMemoryUsage => '.1.3.6.1.4.1.9.9.618.1.8.6.0',
	clsSysCurrentCpuUsage => '.1.3.6.1.4.1.9.9.618.1.8.8.0',
};

# ftp://ftp.cisco.com/pub/mibs/v2/AIRESPACE-WIRELESS-MIB.my
#   bsnAPTable
my $OIDS_AP_INFO = {
	bsnAPName => '.1.3.6.1.4.1.14179.2.2.1.1.3',
	bsnApIpAddress => '.1.3.6.1.4.1.14179.2.2.1.1.19',
	bsnAPStaticIPAddress => '.1.3.6.1.4.1.14179.2.2.1.1.28',
	bsnAPModel => '.1.3.6.1.4.1.14179.2.2.1.1.16',
	bsnAPLocation => '.1.3.6.1.4.1.14179.2.2.1.1.4',
	bsnAPOperationStatus => '.1.3.6.1.4.1.14179.2.2.1.1.6',
};


my $OIDS_AP_IF_STATE = {
	#  bsnAPIfTable
	bsnAPIfType => '.1.3.6.1.4.1.14179.2.2.2.1.2',
	bsnApIfNoOfUsers => '.1.3.6.1.4.1.14179.2.2.2.1.15',
};

my $AP_STATUS = {
	1 => 'Up',
	2 => 'Down',
	3 => 'Downloading'
};

# Channel Physical type
my $AP_PHY_TYPE = {
	1 => "dot11bg",
	2 => "dot11a",
	3 => "uwb",
};

#----------------------------------------
# Sub/functions
#----------------------------------------
sub sanitize_fname($)
{
	my $name = shift;
	$name =~ s/[^0-9a-z_-]/_/gi;
	return $name;
}

# Satinize alias
sub sanitize_alias($)
{
	my $name = shift;
	$name =~ s/\|/ /gi;
	# $name =~ s/\]/ /gi;
	$name =~ s/\=/-/gi;
	return $name;
}

sub dec2hex($)
{
	my $dec = shift or die;
	my $dec_hex = sprintf "%02X-%02X-%02X-%02X-%02X-%02X", split(/\./ , $dec);
	return uc $dec_hex;
}

sub hex2dec($)
{
	my $dec_hex = shift or die;
	my $dec = sprintf "%d.%d.%d.%d.%d.%d", map( hex( $_ ), split( '-', $dec_hex ) );
	return uc $dec;
}

sub format_mac($)
{
   my $mac_octet = shift or die;
   return uc sprintf("%s-%s-%s-%s-%s-%s", unpack('H2' x 6, $mac_octet));
}

sub get_cached_ap($$$)
{
	my $np = shift or die;
	my $hostname = shift or die;
	my $macdec = shift or die;
	my $fd;
	my $datafile = $np->opts->datadir . '/check_cisco_wlc/' . $hostname . '/' . sanitize_fname($macdec) . '.dat';
	
	return undef if (!-e $datafile);

	if (!open($fd, '<', $datafile))
	{
		$np->nagios_die("unable to open datafile '$datafile': $!");
	}
	read($fd, my $content, 8192);
	close($fd);

	my $data = eval($content);
	$np->nagios_die("invalid data in datafile '$datafile': $@") if $@;
	return $data;

	return undef;
}

sub save_cached_ap($$$$)
{
	my $np = shift or die;
	my $hostname = shift or die;
	my $ap_mac = shift or die;
	my $apinfo = shift or die;
	my $fd;

	if (! -d ($np->opts->datadir . '/check_cisco_wlc/' . $hostname))
	{
		if (! -d ($np->opts->datadir . '/check_cisco_wlc'))
		{
			mkdir $np->opts->datadir . '/check_cisco_wlc'
				or $np->nagios_die($!);
		}
		mkdir $np->opts->datadir . '/check_cisco_wlc/' . $hostname
			or $np->nagios_die($!);
	}

	my $datafile = $np->opts->datadir . '/check_cisco_wlc/' . $hostname . '/' . sanitize_fname($ap_mac) . '.dat';
	
	if (!open($fd, '>', $datafile . '.new'))
	{
		$np->nagios_die("unable to open datafile '$datafile.new': $!");
	}

	print $fd Data::Dumper->new([$apinfo])->Terse(1)->Purity(1)->Dump();
	close($fd);
	if (!rename($datafile . '.new', $datafile))
	{
		$np->nagios_die("unable to rename datafile '$datafile.new' to '$datafile': $!");
	}
}

sub get_ap_index_from_oid($)
{
	my $oid = shift or die;
	my ($ap_index) = $oid =~ /(\.[^.]+)$/;
	$ap_index = substr($ap_index, 1);
	return $ap_index;
}

sub get_all_ap_info($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_AP_INFO;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	
	my $list_ap = {};
	# Get AP detail info from     bsnAPTable
	my $result = $snmp_session->get_entries(-columns => [@oids_list]);
	$np->nagios_die("get_all_ap_info:" . $snmp_session->error()) if (!defined $result);
	
	foreach my $item (keys %$result)
	{
		foreach my $oid (keys %$oids)
		{
			my $ap_index = substr($item, length($oids->{$oid})+1);
			my $item_oid = substr($item, 0, length($item) - length($ap_index) -1);
			# print "$oid:$ap_index\n";
			if ($item_oid eq $oids->{$oid})
			{
				my $mac = dec2hex($ap_index);
				my $ap_info = $list_ap->{$mac};
				my $value = $result->{$item};
				if ($value =~ /Not Available/)
				{
					$value = "";
				}
				# print "$oid:$ap_index:$mac:$item:$value\n";				
				$ap_info->{$oid} = uc $value;
				$list_ap->{$mac} = $ap_info;	
				
				last;							
			}
		}
	}
	return $list_ap;
}

sub get_all_ap_if_state($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_AP_IF_STATE;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	
	my $list_ap = {};
	# Get AP detail info from  bsnAPIfTable
	my $result = $snmp_session->get_entries(-columns => [@oids_list]);
	$np->nagios_die("get_all_ap_if_state:" . $snmp_session->error()) if (!defined $result);
	
	foreach my $item (keys %$result)
	{
		my $ap_index = get_ap_index_from_oid($item);
		foreach my $oid (keys %$oids)
		{
			
			my $item_sub = substr($item, 0, length($item) - length($ap_index) -1);
			my $mac_dec = substr($item_sub, length($oids->{$oid})+1);
			my $item_oid = substr($item_sub, 0, length($item_sub) - length($mac_dec) -1);	
			
			if ($item_oid eq $oids->{$oid})
			{
				my $mac = dec2hex($mac_dec);
				my $ap_info = $list_ap->{$mac};
				my $ap_if_info = {};
				if (defined $ap_info)
				{
					$ap_if_info = $ap_info->{$ap_index};
				}
				my $value = $result->{$item};
				if ($value =~ /Not Available/)
				{
					$value = "";
				}
				$ap_if_info->{$oid} = uc $value;
				# print "$oid:$ap_index:$mac:$value\n";				
				$ap_info->{$ap_index} = $ap_if_info;
				$list_ap->{$mac} = $ap_info;	
				last;							
			}
		}
	}
	return $list_ap;
}

sub get_all_aps($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	# Get AP state
	my $list_ap = get_all_ap_info($np, $snmp_session);
	my $list_ap_if = get_all_ap_if_state($np, $snmp_session);
	my $num_ap = keys %$list_ap;
	# Merge 2 list list_ap and list_ap_if
	for my $ap_mac (sort keys %$list_ap)
	{
		my $ap_info = $list_ap->{$ap_mac};
		
		if (defined $list_ap_if->{$ap_mac})
		{
			$ap_info->{"ap_if"} = $list_ap_if->{$ap_mac};
		}
		$ap_info->{time} = time;
		save_cached_ap($np, $np->opts->hostname, $ap_mac, $ap_info);
	}	 
	return $list_ap;
}


sub get_list_ap($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my $index = 0;
	my $list_ap = get_all_ap_info($np, $snmp_session);
	$snmp_session->close();
	foreach my $ap_mac (sort keys %$list_ap)
	{
		my $ap_info = $list_ap->{$ap_mac};
		$index = $index + 1;
		$ap_info->{bsnAPName} = sanitize_alias($ap_info->{bsnAPName});
		if ($index<= $MAX_ENTRIES)
		{
			print "$index: [$ap_mac] [$ap_info->{bsnAPName}] [$ap_info->{bsnAPLocation}] [$ap_info->{bsnApIpAddress}]\n";
		}
		#----------------------------------------
		# Performance Data
		#----------------------------------------
		if (!$np->opts->noperfdata)
		{
			$np->add_perfdata(label => "$ap_mac|$ap_info->{bsnAPName}|$ap_info->{bsnApIpAddress}", 
					value => 1, 
					);
		}
	}
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $metrics = sprintf("Total - %d APs",
				$index,
	);

	#----------------------------------------
	# Print out result
	#----------------------------------------
	my $code;

	my $prefix = " ";

	$np->add_message(OK,'');
	my ($exit_code, $exit_message) = $np->check_messages();

	$exit_message = $prefix . join(' ', ($exit_message, $metrics));
	$exit_message =~ s/^ *//;

	$np->nagios_exit($exit_code, $exit_message);

}

sub get_wlc($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	# Get WLC general information from  clsSysInfo
	my $oids = $OIDS_WLC;
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	my $result = $snmp_session->get_request(-varbindlist => [@oids_list]);
	$np->nagios_die("get_wlc:". $snmp_session->error()) if (!defined $result);
	my $wlc_name = $result->{$oids->{sysName}};
	# my $wlc_model = $result->{$oids->{agentInventoryMachineModel}};
	# my $wlc_num_connected_ap = $result->{$oids->{clsSysApConnectCount}};
	my $wcl_memory_usage = $result->{$oids->{clsSysCurrentMemoryUsage}};
	my $wcl_cpu_usage = $result->{$oids->{clsSysCurrentCpuUsage}};

	if ($wcl_memory_usage eq "noSuchObject")
	{
		$wcl_memory_usage = 0;	
	}

	if ($wcl_cpu_usage eq "noSuchObject")
	{
		$wcl_cpu_usage = 0;	
	}

	

	# Get all APs detail and cached	 
	my $list_ap = get_all_aps($np, $snmp_session);
	my $wlc_num_user = 0;
	my $wlc_num_ap = keys %$list_ap;
	my $wlc_num_connected_ap = 0;
	for my $ap_mac (sort keys %$list_ap)
	{
		my $ap_info = $list_ap->{$ap_mac};
		if (defined $ap_info->{"ap_if"})
		{
			my $ap_if = $ap_info->{"ap_if"};
			if ($ap_info->{bsnAPOperationStatus} == 1)
			{
				$wlc_num_connected_ap ++;
			}
			foreach my $ap_index (keys %$ap_if)
			{
				if (defined $ap_if->{$ap_index}->{bsnApIfNoOfUsers})
				{
					$wlc_num_user += $ap_if->{$ap_index}->{bsnApIfNoOfUsers};
				}
			}
		}
	}	
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $metrics = sprintf("%s - %d APs up/%d APs - %d users - %d%% RAM - %d%% CPU",
				$wlc_name,
				# $wlc_model,
				$wlc_num_connected_ap,
				$wlc_num_ap,
				$wlc_num_user,
				$wcl_memory_usage,
				$wcl_cpu_usage
	);
	
	#----------------------------------------
	# Performance Data
	#----------------------------------------
	if (!$np->opts->noperfdata)
	{
		$np->add_perfdata(label => "num_ap", 
				value => $wlc_num_ap, 
				);
		$np->add_perfdata(label => "num_connected_ap", 
				value => $wlc_num_connected_ap, 
				);		
		$np->add_perfdata(label => "num_user", 
				value => $wlc_num_user, 
				);		
		$np->add_perfdata(label => "memory_usage", 
				value => $wcl_memory_usage, 
				);								
		$np->add_perfdata(label => "cpu_usage", 
				value => $wcl_cpu_usage, 
				);										
	}
	#----------------------------------------
	# Print out result
	#----------------------------------------
	my $code;

	my $prefix = " ";

	$np->add_message(OK,'');
	my ($exit_code, $exit_message) = $np->check_messages();

	$exit_message = $prefix . join(' ', ($exit_message, $metrics));
	$exit_message =~ s/^ *//;
	$snmp_session->close();
	$np->nagios_exit($exit_code, $exit_message);
}

sub get_ap($$$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my $ap_mac = shift or die;
	my $ap_info = get_cached_ap($np, $np->opts->hostname, $ap_mac);
	my $mac_dec = hex2dec($ap_mac);
	# print "Get cache for:$ap_mac \n";
	if (!defined $ap_info)
	{
		# Renew cache
		get_all_aps($np, $snmp_session);
		$ap_info = get_cached_ap($np, $np->opts->hostname, $ap_mac);
		if (!defined $ap_info)
		{
			$np->nagios_exit(3, "Can not get cached");
		}
	}
	else
	{
		my $time_delta = time - $ap_info->{time};
		# print "time delta:$time_delta\n";
		if ($time_delta > $CACHE_EXPIRED)
		{
			print "Cached expired:$time_delta\n";
			# Check AP status
			my $oid = "$OIDS_AP_INFO->{bsnAPOperationStatus}.$mac_dec";
			# print "oid:$oid\n";
			my $result = $snmp_session->get_request(-varbindlist => [$oid]);
			if (!defined $result)
			{
				$ap_info->{bsnAPOperationStatus} = 2;
				print "Can not query bsnAPOperationStatus" . $snmp_session->error();
			}
			else
			{
				if ($result->{$oid}==1)
				{
					print "Renew cache to double check\n";
					# Renew cache to double check
					get_all_aps($np, $snmp_session);
					$ap_info = get_cached_ap($np, $np->opts->hostname, $ap_mac);
				}
				else {
					$ap_info->{bsnAPOperationStatus} = 2;
				}
			}
		}
	}

	#----------------------------------------
	# Performance Data
	#----------------------------------------
	my $num_user = 0;
	if (!$np->opts->noperfdata)
	{
		$np->add_perfdata(label => "ap_status", 
				value => $ap_info->{bsnAPOperationStatus}, 
				critical => "~:1"
				);
		# perf data for each network
		if (defined $ap_info->{"ap_if"})
		{
			my $ap_if = $ap_info->{"ap_if"};
			foreach my $ap_index (keys %$ap_if)
			{
				my $ap_if_info = $ap_if->{$ap_index};
				my $phy_type_int = $ap_if_info->{bsnAPIfType};	
				my $phy_type = $AP_PHY_TYPE->{$phy_type_int};
				$num_user = $num_user + $ap_if_info->{bsnApIfNoOfUsers};
				$np->add_perfdata(label => "num_user_" . $phy_type, 
					value => $ap_if_info->{bsnApIfNoOfUsers}, 
					);		
			}
		}

		# Total users of AP
		$np->add_perfdata(label => "num_user", 
				value => $num_user, 
				);		
		
	}	

	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $ap_status =  $AP_STATUS->{$ap_info->{bsnAPOperationStatus}};
	my $metrics = sprintf("%s [%s] [%s] [%s] [%s] [%s] - %s - %d users",
				$ap_info->{bsnAPName},
				$ap_mac,
				$mac_dec,
				$ap_info->{bsnAPModel},
				$ap_info->{bsnAPLocation},
				$ap_info->{bsnApIpAddress},
				$ap_status,
				$num_user,
	);

	
	#----------------------------------------
	# Status Checks
	#----------------------------------------

	my $code;
	my $prefix = " ";
	$np->add_message(OK,'');
	
	if (($code = $np->check_threshold(
			check => $ap_info->{bsnAPOperationStatus}, 
			# warning => "~:1", 
			critical => "~:1")) != OK)
		{
			$np->add_message($code, $prefix . '[STATUS]');
		}
	my ($exit_code, $exit_message) = $np->check_messages();	
	$exit_message = $prefix . join(' ', ($exit_message, $metrics));
	$exit_message =~ s/^ *//;
	$snmp_session->close();
	$np->nagios_exit($exit_code, $exit_message);
}

#----------------------------------------
# Main program 
#----------------------------------------
my $np = Nagios::Monitoring::Plugin->new(
	shortname => 'CISCO-WLC',
	usage => "usage: check_cisco_wlc.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'CISCO-WLC',
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
	default => 1,
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
$np->add_arg(
	spec => 'modes',
	help => "--modes\n   List check modes.",
);

$np->add_arg(
	spec => 'mode|m=s',
	help => "-m, --mode\n   Check modes.",
	required => 1,
	default => 'wlc',
);

# AP params
$np->add_arg(
	spec => 'mac=s',
	help => "mac of AP.",
);

# Threshold
# $np->add_arg(
# 	spec => 'powerdelta=f',
# 	help => "max_power=PwrHiAlarm - powerdelta\n min_power=PwrLowAlarm + powerdelta\n",
# );

# $np->add_arg(
# 	spec => 'currentdelta=f',
# 	help => "max_current=CurrentHiAlarm - currentdelta\n min_current=CurrentLowAlarm + currentdelta\n",
# );

# $np->add_arg(
# 	spec => 'tempdelta=f',
# 	help => "max_temperature=tempHiAlarm - tempdelta\n min_current=tempLowAlarm + tempdelta\n",
# );
$np->getopts();

# Safety Net
alarm $np->opts->timeout;

#----------------------------------------
# List mode
#----------------------------------------
if (defined $np->opts->modes)
{
	print "Mode list:\n";
	print "wlc: check Virtual Controller state \n";
	print "list-ap: list access points of WLC \n";
	print "ap: check Access Point state \n";
	print "all-aps: check all Access Points state \n";
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
# Cache Directory
#----------------------------------------

if (! -w $np->opts->datadir)
{
	$np->nagios_die("Unable to write to data directory" . $np->opts->datadir);
}

#----------------------------------------
# Virtual Controller mode
#----------------------------------------
if ($np->opts->mode eq "wlc")
{
	get_wlc($np, $snmp_session);
}
elsif ($np->opts->mode eq "list-ap")
{
	get_list_ap($np, $snmp_session);
}
elsif ($np->opts->mode eq "ap")
{
	get_ap($np, $snmp_session,$np->opts->mac);
}


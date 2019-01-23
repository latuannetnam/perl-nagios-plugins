#!/usr/bin/perl
#
#    check_ruskus_zd nagios plugin: Monitor Ruskus ZD controller
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

my $OIDS_SYSTEM = {
	 sysDescr => '.1.3.6.1.2.1.1.1.0',
	 sysObjectID => '.1.3.6.1.2.1.1.2.0',
	 sysName => '.1.3.6.1.2.1.1.5.0',
};


my $OIDS_WLC = {
	#   ruckusZDSystemInfo
	ruckusZDSystemName => '.1.3.6.1.4.1.25053.1.2.1.1.1.1.1.0',
	ruckusZDSystemModel => '.1.3.6.1.4.1.25053.1.2.1.1.1.1.9.0',
	#  ruckusZDSystemStats
	ruckusZDSystemStatsNumAP => '.1.3.6.1.4.1.25053.1.2.1.1.1.15.1.0',
	ruckusZDSystemStatsNumSta => '.1.3.6.1.4.1.25053.1.2.1.1.1.15.2.0',
	ruckusZDSystemStatsNumRogue => '.1.3.6.1.4.1.25053.1.2.1.1.1.15.3.0',
	ruckusZDSystemStatsCPUUtil => '.1.3.6.1.4.1.25053.1.2.1.1.1.15.13.0',
	ruckusZDSystemStatsMemoryUtil => '.1.3.6.1.4.1.25053.1.2.1.1.1.15.14.0',
};

#   ruckusZDSystemExpInfo
my $OIDS_WLC_STATE = {
	ruckusZDSystemCPUUtil => '.1.3.6.1.4.1.25053.1.2.1.1.1.5.58.0',
	ruckusZDSystemMemoryUtil => '.1.3.6.1.4.1.25053.1.2.1.1.1.5.59.0',
	ruckusZDSystemMemorySize => '.1.3.6.1.4.1.25053.1.2.1.1.1.5.60.0',
};


my $OIDS_AP = {
	# ruckusZDWLANAPTable
	ruckusZDWLANAPDescription => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.2.6',
	ruckusZDWLANAPIPAddr => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.10.6',
};

# ruckusZDWLANAPTable
my $OIDS_AP_STATE = {
	ruckusZDWLANAPDescription => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.2.6',
	ruckusZDWLANAPIPAddr => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.10.6',
	ruckusZDWLANAPModel => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.4.6',
	ruckusZDWLANAPStatus => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.3.6',
	ruckusZDWLANAPNumSta => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.15.6',
	ruckusZDWLANAPNumRogues => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.16.6',
	ruckusZDWLANAPMemUtil => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.27.6',
	ruckusZDWLANAPMemTotal => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.28.6',
	ruckusZDWLANAPCPUUtil => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.29.6',
	ruckusZDWLANAPLANStatsRXByte => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.21.6',
	ruckusZDWLANAPLANStatsRXPkt => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.22.6',
	ruckusZDWLANAPLANStatsRXPktErr => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.23.6',
	ruckusZDWLANAPLANStatsTXByte => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.25.6',
	ruckusZDWLANAPLANStatsTXPkt => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.26.6',
	ruckusZDWLANAPLANStatsDropped => '.1.3.6.1.4.1.25053.1.2.2.1.1.2.1.1.53.6'
};



my $AP_STATUS = {
	0 => 'Down',
	1 => 'Up',
	2 => 'Pending',
	3 => 'Upgrading'
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

sub dec2hex($)
{
	my $dec = shift or die;
	my $dec_hex = sprintf "%X:%X:%X:%X:%X:%X", split(/\./ , $dec) ;
	return uc $dec_hex;
}

sub hex2dec($)
{
	my $dec_hex = shift or die;
	my $dec = sprintf "%d.%d.%d.%d.%d.%d", map( hex( $_ ), split( ':', $dec_hex ) );
	return uc $dec;
}

sub get_wlc($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	# Get VC general information
	my $oids = $OIDS_WLC;
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	my $result = $snmp_session->get_request(-varbindlist => [@oids_list]);
	$snmp_session->close();
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	my $wlc_name = $result->{$oids->{ruckusZDSystemName}};
	my $wlc_model = $result->{$oids->{ruckusZDSystemModel}};
	my $wlc_num_ap = $result->{$oids->{ruckusZDSystemStatsNumAP}};
	my $wlc_num_user = $result->{$oids->{ruckusZDSystemStatsNumSta}};
	my $wlc_num_rougue_user = $result->{$oids->{ruckusZDSystemStatsNumRogue}};
	my $wcl_memory_usage = $result->{$oids->{ruckusZDSystemStatsMemoryUtil}};
	my $wcl_cpu_usage = $result->{$oids->{ruckusZDSystemStatsCPUUtil}};
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $metrics = sprintf("%s [%s] - %d APs - %d users - %d rougue users - %d%% RAM - %d%% CPU",
				$wlc_name,
				$wlc_model,
				$wlc_num_ap,
				$wlc_num_user,
				$wlc_num_rougue_user,
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
		$np->add_perfdata(label => "num_user", 
				value => $wlc_num_user, 
				);		
		$np->add_perfdata(label => "num_rougue_user", 
				value => $wlc_num_rougue_user, 
				);
		$np->add_perfdata(label => "memory_usage", 
				value => $wcl_memory_usage, 
				);								
		$np->add_perfdata(label => "cpu_usage", 
				value => $wcl_memory_usage, 
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

	$np->nagios_exit($exit_code, $exit_message);
}

sub get_list_ap($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	# Get list AP from  wlsxSwitchAccessPointTable
	my $result = $snmp_session->get_table(-baseoid => $OIDS_AP->{ruckusZDWLANAPIPAddr});
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	my $list_ap = {};
	foreach my $item (keys %$result)
	{
		my $ap_info = {};
		my $ap_index = substr($item, length($OIDS_AP->{ruckusZDWLANAPIPAddr})+1);
		# print "$ap_index:", uc $result->{$item}, "\n";
		my $mac_hex = dec2hex($ap_index);
		$ap_info->{'ipAddress'} = $result->{$item};
		$ap_info->{'mac'} = $mac_hex;
		# print "$dec_hex: $result->{$item}\n";
		$list_ap->{$ap_index} = $ap_info;
	}

	# Get AP detail info from  wlsxWlanAPTable
	$result = $snmp_session->get_table(-baseoid => $OIDS_AP->{ruckusZDWLANAPDescription});
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	foreach my $item (keys %$result)
	{
		my $ap_index = substr($item, length($OIDS_AP->{ruckusZDWLANAPDescription})+1);
		# print "$ap_index:", uc $result->{$item}, "\n";
		if ($list_ap->{$ap_index})
		{
			my $ap_info = $list_ap->{$ap_index};
			$ap_info->{'apName'} = uc $result->{$item};
			$list_ap->{$ap_index} = $ap_info;
			# print $result->{$item}, " abc \n";
		}
		
	}
	$snmp_session->close();


	
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $size = keys %$list_ap;
	my $metrics = sprintf("Total - %d APs",
				$size,
	);
	my $index = 1;
	foreach my $item (keys %$list_ap)
	{
		my $ap_info = $list_ap->{$item};
		print "$index: $ap_info->{apName} [$ap_info->{mac}] $ap_info->{ipAddress}\n";
		$index = $index + 1;
		#----------------------------------------
		# Performance Data
		#----------------------------------------
		if (!$np->opts->noperfdata)
		{
			$np->add_perfdata(label => "[$ap_info->{apName}] [$ap_info->{mac}] [$ap_info->{ipAddress}]", 
					value => 1, 
					);
		}
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

	$np->nagios_exit($exit_code, $exit_message);

}
sub get_cached_ap($$$)
{
	my $np = shift or die;
	my $hostname = shift or die;
	my $macdec = shift or die;
	my $fd;
	my $datafile = $np->opts->datadir . '/check_ruckus_zd/' . $hostname . '/' . sanitize_fname($macdec) . '.dat';
	
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
	my $apmac = shift or die;
	my $apinfo = shift or die;
	my $fd;

	if (! -d ($np->opts->datadir . '/check_ruckus_zd/' . $hostname))
	{
		if (! -d ($np->opts->datadir . '/check_ruckus_zd'))
		{
			mkdir $np->opts->datadir . '/check_ruckus_zd'
				or $np->nagios_die($!);
		}
		mkdir $np->opts->datadir . '/check_ruckus_zd/' . $hostname
			or $np->nagios_die($!);
	}

	my $datafile = $np->opts->datadir . '/check_ruckus_zd/' . $hostname . '/' . sanitize_fname($apmac) . '.dat';
	
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

sub get_ap($$$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my $apmac = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_AP_STATE;
	my $macdec = hex2dec($apmac);
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}.$macdec";
	}
	my $result = $snmp_session->get_request(-varbindlist => [@oids_list]);
	$snmp_session->close();
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	my $ap_info = {};

	foreach my $item (keys %$oids)
	{
		$ap_info->{$item} = $result->{"$oids->{$item}.$macdec"};
		print $item, ":", $ap_info->{$item}, "\n";
	}
	my $cached_ap = get_cached_ap($np, $np->opts->hostname, $macdec);
	$ap_info->{time} = time;
	save_cached_ap($np, $np->opts->hostname, $macdec, $ap_info);
	
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $ap_status =  $AP_STATUS->{$ap_info->{ruckusZDWLANAPStatus}};
	my $metrics = sprintf("%s [%s] - %s - %d users - %0.2f%% RAM - %d%% CPU",
				$ap_info->{ruckusZDWLANAPDescription},
				$ap_info->{ruckusZDWLANAPIPAddr},
				$ap_status,
				$ap_info->{ruckusZDWLANAPNumSta},
				$ap_info->{ruckusZDWLANAPMemUtil}/$ap_info->{ruckusZDWLANAPMemTotal}*100,
				$ap_info->{ruckusZDWLANAPCPUUtil},
	);

	#----------------------------------------
	# Performance Data
	#----------------------------------------
	if (!$np->opts->noperfdata)
	{
		$np->add_perfdata(label => "num_user", 
				value => $ap_info->{ruckusZDWLANAPNumSta}, 
				# warning => $np->opts->whlscrc, 
				# critical => $np->opts->chlscrc
				);
		$np->add_perfdata(label => "memory_usage", 
				value => sprintf("%0.2f",$ap_info->{ruckusZDWLANAPMemUtil}/$ap_info->{ruckusZDWLANAPMemTotal}*100) 
				);		
		$np->add_perfdata(label => "cpu_usage", 
				value => sprintf("%0.2f",$ap_info->{ruckusZDWLANAPCPUUtil}) 
				);				
	}	
	#----------------------------------------
	# Status Checks
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
	shortname => 'RUCKUS-ZD',
	usage => "usage: check_ruckus_zd.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'RUCKUS-ZD',
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
	print "wlc: check Virtual Controller state \n";
	print "list-ap: list access points of WLC \n";
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
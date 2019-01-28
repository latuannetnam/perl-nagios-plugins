#!/usr/bin/perl
#
#    check_aruba_wlc nagios plugin: Monitor Aurba Wireless Mobility Controllers
#    Copyright (C) 2019 Le Anh Tuan (tuan.la@netnam.vn/latuannetnam@gmail.com)
#	 Credit to: http://udel.edu/~doke/aruba/check_aruba
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
	#  wlsxSystemXGroup
	wlsxHostname => '.1.3.6.1.4.1.14823.2.2.1.1.1.1.0',
	wlsxModelName => '.1.3.6.1.4.1.14823.2.2.1.1.1.2.0',
	wlsxSwitchTotalNumAccessPoints => '.1.3.6.1.4.1.14823.2.2.1.1.3.1.0',
	wlsxTotalNumOfUsers => '.1.3.6.1.4.1.14823.2.2.1.4.1.1.0',
	#  wlsxSystemExtGroup
	wlsxSysExtMemoryUsedPercent => '.1.3.6.1.4.1.14823.2.2.1.2.1.31.0',
	wlsxSysExtCpuUsedPercent => '.1.3.6.1.4.1.14823.2.2.1.2.1.30.0',
	
};

#   wlsxSwitchAccessPointTable
my $OIDS_AP_BSSID = {
	apIpAddress => '.1.3.6.1.4.1.14823.2.2.1.1.3.3.1.5',
	apLocation => '.1.3.6.1.4.1.14823.2.2.1.1.3.3.1.9',
};

#  wlsxWlanAPTable
my $OIDS_AP_INFO = {
	wlanAPName => '.1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.3',
	wlanAPIpAddress => '.1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.2',
	wlanAPModel => '.1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.5',
	wlanAPLocation => '.1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.14',
	wlanAPStatus => '.1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.19',
};

#  wlsxUserTable
my $OIDS_AP_USER = {
	nUserApBSSID => '.1.3.6.1.4.1.14823.2.2.1.4.1.2.1.11'
};

my $OIDS_AP_BSSID_STATE = {
	#  wlsxSwitchAccessPointTable
	apPhyType => '.1.3.6.1.4.1.14823.2.2.1.1.3.3.1.6',
	apIpAddress => '.1.3.6.1.4.1.14823.2.2.1.1.3.3.1.5',
	apChannelNoise => '.1.3.6.1.4.1.14823.2.2.1.1.3.3.1.13',
	apSignalToNoiseRatio => '.1.3.6.1.4.1.14823.2.2.1.1.3.3.1.14',
};

my $OIDS_AP_BSSID_STATE_EXT = {
	#  wlsxWlanAPStatsTable
	wlanAPNumClients => '.1.3.6.1.4.1.14823.2.2.1.5.3.1.1.1.2',
};


my $AP_STATUS = {
	2 => 'Down',
	1 => 'Up',
};

# Channel Physical type
my $AP_PHY_TYPE = {
	1 => "dot11a",
	2 => "dot11b",
	3 => "dot11g",
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
sub get_ap_index_from_oid($)
{
	my $oid = shift or die;
	my ($ap_index) = $oid =~ /(\.[^.]+)$/;
	$ap_index = substr($ap_index, 1);
	return $ap_index;
}

sub get_cached_ap($$$)
{
	my $np = shift or die;
	my $hostname = shift or die;
	my $macdec = shift or die;
	my $fd;
	my $datafile = $np->opts->datadir . '/check_aruba_wlc/' . $hostname . '/' . sanitize_fname($macdec) . '.dat';
	
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

	if (! -d ($np->opts->datadir . '/check_aruba_wlc/' . $hostname))
	{
		if (! -d ($np->opts->datadir . '/check_aruba_wlc'))
		{
			mkdir $np->opts->datadir . '/check_aruba_wlc'
				or $np->nagios_die($!);
		}
		mkdir $np->opts->datadir . '/check_aruba_wlc/' . $hostname
			or $np->nagios_die($!);
	}

	my $datafile = $np->opts->datadir . '/check_aruba_wlc/' . $hostname . '/' . sanitize_fname($ap_mac) . '.dat';
	
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
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	my $wlc_name = $result->{$oids->{wlsxHostname}};
	my $wlc_model = $result->{$oids->{wlsxModelName}};
	my $wlc_num_ap = $result->{$oids->{wlsxSwitchTotalNumAccessPoints}};
	my $wlc_num_user = $result->{$oids->{wlsxTotalNumOfUsers}};
	my $wcl_memory_usage = $result->{$oids->{wlsxSysExtMemoryUsedPercent}};
	my $wcl_cpu_usage = $result->{$oids->{wlsxSysExtCpuUsedPercent}};

	# Get all APs detail and cached	 
	my $wlc_num_connected_ap = get_all_aps($np, $snmp_session);
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $metrics = sprintf("%s [%s] - %d APs up/%d APs - %d users - %d%% RAM - %d%% CPU",
				$wlc_name,
				$wlc_model,
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
		# Only keep AP with status=1
		if ($ap_info->{ wlanAPStatus}>1)
		{
			next;
		}
		
		$index = $index + 1;
		if ($index<= $MAX_ENTRIES)
		{
			print "$index: [$ap_mac] [$ap_info->{wlanAPName}] [$ap_info->{wlanAPLocation}] [$ap_info->{wlanAPIpAddress}]\n";
		}
		#----------------------------------------
		# Performance Data
		#----------------------------------------
		if (!$np->opts->noperfdata)
		{
			$np->add_perfdata(label => "$ap_mac]$ap_info->{wlanAPName}]$ap_info->{wlanAPIpAddress}", 
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

sub get_ap_cached($$$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my $ap_mac = shift or die;
	my $ap_info = get_cached_ap($np, $np->opts->hostname, $ap_mac);
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
			# Renew cache to double check
			get_all_aps($np, $snmp_session);
			$ap_info = get_cached_ap($np, $np->opts->hostname, $ap_mac);
			# $time_delta = time - $ap_info->{time};
			# if ($time_delta > $CACHE_EXPIRED)
			# {
			# 	$ap_info->{wlanAPStatus} = 2;
			# }
		}
		
	}

	#----------------------------------------
	# Performance Data
	#----------------------------------------
	my $num_user = 0;
	if (!$np->opts->noperfdata)
	{
		$np->add_perfdata(label => "ap_status", 
				value => $ap_info->{wlanAPStatus}, 
				critical => "~:1"
				);
		
		# perf data for bssid
		my $ap_bssid = $ap_info->{ap_bssid};
		foreach my $bssid (sort keys %$ap_bssid)
		{
			my $app_bssid_info = $ap_bssid->{$bssid};
			my $phy_type_int = $app_bssid_info->{apPhyType};
			$num_user = $num_user + $app_bssid_info->{wlanAPNumClients};
			if (defined $phy_type_int)
			{
				my $phy_type = $AP_PHY_TYPE->{$phy_type_int};
				
				$np->add_perfdata(label => "num_user_" . $phy_type, 
					value => $app_bssid_info->{wlanAPNumClients}, 
					);		
				$np->add_perfdata(label => "channel_noise_" . $phy_type, 
						value => $app_bssid_info->{apChannelNoise}, 
						);
				$np->add_perfdata(label => "snr_" . $phy_type, 
						value => $app_bssid_info->{apSignalToNoiseRatio}, 
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
	my $ap_status =  $AP_STATUS->{$ap_info->{wlanAPStatus}};
	my $metrics = sprintf("%s [%s] [%s] [%s] - %s - %d users",
				$ap_info->{wlanAPName},
				$ap_mac,
				$ap_info->{wlanAPLocation},
				$ap_info->{wlanAPIpAddress},
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
			check => $ap_info->{wlanAPStatus}, 
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
	# Get AP detail info from    wlsxWlanAPTable
	my $result = $snmp_session->get_entries(-columns => [@oids_list]);
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	
	foreach my $item (keys %$result)
	{
		foreach my $oid (keys %$oids)
		{
			if ($item =~ $oids->{$oid})
			{
				my $ap_index = substr($item, length($oids->{$oid})+1);
				my $mac = dec2hex($ap_index);
				my $ap_info = $list_ap->{$mac};
				my $value = $result->{$item};
				if ($value =~ /Not Available/)
				{
					$value = "";
				}
				if ($oid eq "wlanAPName")
				{
					$value = $value =~ s/:/-/rg;

				}
				$ap_info->{$oid} = uc $value;
				$list_ap->{$mac} = $ap_info;	
				# print "$oid:$ap_index:$mac:$item:$ap_info->{$oid}\n";
				last;							
			}
		}
	}
	return $list_ap;
}

sub get_all_ap_bssid_state($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_AP_BSSID_STATE;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}

	my $result = $snmp_session->get_entries(-columns => [@oids_list]);
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	my $list_ap_bssid = {};
	foreach my $item (keys %$result)
	{
		foreach my $oid (keys %$oids)
		{
			if ($item =~ $oids->{$oid})
			{
				my $ap_index = substr($item, length($oids->{$oid})+1);
				my $mac = dec2hex($ap_index);
				my $ap_info = $list_ap_bssid->{$mac};
				$ap_info->{$oid} = $result->{$item};
				$list_ap_bssid->{$mac} = $ap_info;	
				# print "$oid:$item:$mac:$result->{$item}\n";
				last;				
			}
		}
	}
	return $list_ap_bssid;
}

sub get_all_ap_bssid_state_ext($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my @oids_list = ();
	my $oids = $OIDS_AP_BSSID_STATE_EXT;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}

	my $result = $snmp_session->get_entries(-columns => [@oids_list]);
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	my $list_ap_bssid = {};
	foreach my $item (keys %$result)
	{
		foreach my $oid (keys %$oids)
		{
			if ($item =~ $oids->{$oid})
			{
				# $ap_index: AP_MAC.RADIO_NUMBER:BSSID
				my $ap_index = substr($item, length($oids->{$oid})+1);
				my @octects = split(/\./,$ap_index);
				my @mac_arr = @octects[0..5];
				my $mac = join("-", map { sprintf "%02X", $_ } @mac_arr);
				my @bssid_arr = @octects[7..12];
				my $bssid = join("-", map { sprintf "%02X", $_ } @bssid_arr);
				my $ap_info = $list_ap_bssid->{$bssid};
				$ap_info->{$oid} = $result->{$item};
				$ap_info->{ap_mac} = $mac;
				$list_ap_bssid->{$bssid} = $ap_info;
				# print "$oid:$ap_index:$mac:$bssid:$result->{$item}\n";
				last;				
			}
		}
	}
	return $list_ap_bssid;
}


sub get_ap_mac_from_list($$$)
{
	my $list = shift or die;
	my $key = shift or die;
	my $value = shift or die;
	my @list_mac = ();
	foreach my $ap_mac (keys %$list) {
		my $ap_info = $list->{$ap_mac};
		if ($ap_info->{$key} eq $value)
		{
			push @list_mac, $ap_mac;
		}
			
	}
	return @list_mac;
}
sub get_all_aps($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	# Get AP state
	# Get AP detail info from    wlsxWlanAPStatsTable
	my $list_ap_bssid = get_all_ap_bssid_state($np, $snmp_session);
	my $list_ap = get_all_ap_info($np, $snmp_session);
	my $list_ap_bssid_ext = get_all_ap_bssid_state_ext($np, $snmp_session);
	my $num_connected_ap = 0;
	for my $ap_mac (sort keys %$list_ap)
	{
		my $ap_info = $list_ap->{$ap_mac};
		
		# Only keep AP with status=1
		if ($ap_info->{wlanAPStatus}>1)
		{
			next;
		}
		$num_connected_ap ++;
		# print "$ap_mac:$ap_info->{wlanAPName}:$ap_info->{wlanAPIpAddress}\n";
		# Get all bssid state matching ap ip address
		my $ip_address = $ap_info->{wlanAPIpAddress};
		my @list_mac = get_ap_mac_from_list($list_ap_bssid, "apIpAddress", $ip_address);
		my $ap_bssid = {};
		foreach my $bssid (@list_mac)
		{
			my $ap_bssid_info = $list_ap_bssid->{$bssid};
			my $ap_bssid_info_ext = $list_ap_bssid_ext->{$bssid};
			# Merge 2 ap bssid
			if (defined $ap_bssid_info_ext)
			{
				$ap_bssid->{$bssid} = {%$ap_bssid_info, %$ap_bssid_info_ext} ;	
			}
			else
			{
				$ap_bssid->{$bssid} = $ap_bssid_info;
			}
			
			# print "$bssid:$ap_bssid_info->{apPhyType}:$ap_bssid_info->{apChannelNoise}\n";
		}
		# Get all bssid ext state matching ap mac
		@list_mac = get_ap_mac_from_list($list_ap_bssid_ext, "ap_mac", $ap_mac);
		my $ap_bssid_ext = {};
		foreach my $bssid (@list_mac)
		{
			my $ap_bssid_info_ext = $list_ap_bssid_ext->{$bssid};
			my $ap_bssid_info = $ap_bssid->{$bssid};
			# Merge 2 ap bssid
			if (defined $ap_bssid_info)
			{
				$ap_bssid_ext->{$bssid} = {%$ap_bssid_info, %$ap_bssid_info_ext} ;
			}
			else
			{
				$ap_bssid_ext->{$bssid} = $ap_bssid_info_ext;
			}
			
			# print "$bssid:$$ap_bssid_ext->{$bssid}->{wlanAPNumClients}\n";
		}
		$ap_info->{ap_bssid} = $ap_bssid_ext;
		$ap_info->{time} = time;
		save_cached_ap($np, $np->opts->hostname, $ap_mac, $ap_info);
	}
  return $num_connected_ap;
}

sub get_all_aps_old($$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	# Get AP state
	my @oids_list = ();
	my $oids = $OIDS_AP_BSSID_STATE;
	
	foreach my $item (keys %$oids)
	{
		push @oids_list, "$oids->{$item}";
	}
	
	my $list_ap = {};
	# Get AP detail info from   wlsxSwitchAccessPointEntry
	my $result = $snmp_session->get_entries(-columns => [@oids_list]);
	$np->nagios_die($snmp_session->error()) if (!defined $result);
	
	foreach my $item (keys %$result)
	{
		foreach my $oid (keys %$oids)
		{
			if ($item =~ $oids->{$oid})
			{
				my $ap_index = substr($item, length($oids->{$oid})+1);
				my $mac = format_mac($ap_index);
				my $ap_info = $list_ap->{$mac};
				$ap_info->{$oid} = $result->{$item};
				$list_ap->{$mac} = $ap_info;	
				# print "$oid:$item:$mac:$result->{$item}\n";
				last;				
			}
		}
	}
	
	# Get connected users for each BSSID
	$result = $snmp_session->get_table(-baseoid => $OIDS_AP_USER->{nUserApBSSID});
	my $num_user = 0;
	my $total_user = 0;
	if (defined $result)
	{
		
		foreach my $item (keys %$result)
		{
			my $mac = format_mac($result->{$item});
			my $ap_info = $list_ap->{$mac};
			$num_user = $ap_info->{numUser};
			if (!defined $num_user)
			{
				$num_user = 0;
			}
			$num_user = $num_user + 1;
			$ap_info->{numUser} = $num_user;
			$total_user = $total_user + 1;
			$list_ap->{$mac} = $ap_info;
		}
		
	}
	
	$snmp_session->close();
	#----------------------------------------
	# Metrics Summary
	#----------------------------------------
	my $total_ap = keys %$list_ap;
	my $metrics = sprintf("%d BSSIDs - %d users",
			$total_ap,
			$total_user,
	);
	#----------------------------------------
	# Performance Data
	#----------------------------------------
	if (!$np->opts->noperfdata)
	{
		foreach my $ap_mac (sort keys %$list_ap)
		{
			my $ap_info = $list_ap->{$ap_mac};
			
			if (!defined $ap_info->{numUser})
			{
				$ap_info->{numUser} = 0;
			}
			if (!defined $ap_info->{apChannelNoise})
			{
				$ap_info->{apChannelNoise} = 0;
			}
			if (!defined $ap_info->{apSignalToNoiseRatio})
			{
				$ap_info->{apSignalToNoiseRatio} = 0;
			}

			$np->add_perfdata(label => "user_" . $ap_mac, 
					value => $ap_info->{numUser}, 
					);
			$np->add_perfdata(label => "noise_" . $ap_mac, 
					value => $ap_info->{apChannelNoise}, 
					);		
			$np->add_perfdata(label => "snr_" . $ap_mac, 
					value => $ap_info->{apSignalToNoiseRatio}, 
					);		
		}
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
	shortname => 'ARUBA-WLC',
	usage => "usage: check_aruba_instant.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'ARUBA-WLC',
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
	get_ap_cached($np, $snmp_session,$np->opts->mac);
}


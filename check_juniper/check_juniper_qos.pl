#!/usr/bin/perl
#
#    check_juniper_qos nagios plugin: Monitor Cisco Wireless controller
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

my $OIDS_UPLOAD_QOS = {
	jnxFWCounterDisplayName => '.1.3.6.1.4.1.2636.3.5.2.1.7',
    jnxFWCounterPacketCount => '.1.3.6.1.4.1.2636.3.5.2.1.4',
	jnxFWCounterByteCount => '.1.3.6.1.4.1.2636.3.5.2.1.5',
};

my $OIDS_DOWNLOAD_QOS = {
    jnxScuStatsClName => '.1.3.6.1.4.1.2636.3.16.1.1.1.6',
    jnxScuStatsPackets => '.1.3.6.1.4.1.2636.3.16.1.1.1.4',
    jnxScuStatsBytes => '.1.3.6.1.4.1.2636.3.16.1.1.1.5', 
};


#----------------------------------------
# Sub/functions
#----------------------------------------

sub oid_to_ascii ($)
{
	## Convert each two-digit hex number back to an ASCII character.
	my @noDotArry = split(/\./,$_[0]);
	my $str = "";
	foreach (@noDotArry){
		if ($_ ne "") {
			$str .= chr($_);
		}
	}
	return $str;
}

sub unit_value
{
	my $value = shift;
	my $unit = (shift or '');
	my $multiplier = (shift or 1000);
	my $digits = (shift or 2);
	my @symbols = ('', 'k', 'M', 'G', 'T', 'P');
	my $sidx = 0;

	while ($value >= $multiplier && $sidx < @symbols)
	{
		$value /= $multiplier;
		$sidx++;
	}

	return sprintf("%.${digits}f%s%s", $value, $symbols[$sidx], $unit);
}

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

sub get_cached($$$)
{
	my $np = shift or die;
	my $hostname = shift or die;
	my $filter = shift or die;
	my $fd;
	my $datafile = $np->opts->datadir . '/check_juniper_qos/' . $hostname . '/' . $filter . '.dat';
	
	return undef if (!-e $datafile);
	my $data = retrieve($datafile);
	return $data;
}

sub save_cached($$$$)
{
	my $np = shift or die;
	my $hostname = shift or die;
	my $filter = shift or die;
    my $filterinfo = shift or die;
	my $fd;

	if (! -d ($np->opts->datadir . '/check_juniper_qos/' . $hostname))
	{
		if (! -d ($np->opts->datadir . '/check_juniper_qos'))
		{
			mkdir $np->opts->datadir . '/check_juniper_qos'
				or $np->nagios_die($!);
		}
		mkdir $np->opts->datadir . '/check_juniper_qos/' . $hostname
			or $np->nagios_die($!);
	}

	my $datafile = $np->opts->datadir . '/check_juniper_qos/' . $hostname . '/' . $filter . '.dat';
	
	# if (!open($fd, '>', $datafile . '.new'))
	# {
	# 	$np->nagios_die("unable to open datafile '$datafile.new': $!");
	# }

	# print $fd Data::Dumper->new([$filterinfo])->Terse(1)->Purity(1)->Useqq(1)->Dump();
	# close($fd);
	# if (!rename($datafile . '.new', $datafile))
	# {
	# 	$np->nagios_die("unable to rename datafile '$datafile.new' to '$datafile': $!");
	# }
	store $filterinfo, $datafile;
}



sub get_filter_list_blocking($$$$)
{
    my $np = shift or die;
	my $snmp_session = shift or die;
	my $mode = shift or die;
	my $nonblocking = shift or die;
    my $oid = shift or die;
    my $result = $snmp_session->get_entries(-columns => [$oid], -maxrepetitions => 10);
	$np->nagios_die("get_filter_list:" . $snmp_session->error()) if (!defined $result);
	$snmp_session->close();
    # print Dumper($result);
    # my @filter_list = sort values %$result;
    
    my $filter_list = {};
    foreach my $item (sort {$result->{$a} cmp $result->{$b}} keys %$result)
	{
        my $filterID  = substr($item, length($oid) + 1 , length($item) - length($oid) - 1 );
        $filter_list->{$filterID} = $result->{$item};
        $np->add_perfdata(label => "$result->{$item}|$filterID", 
                value => 1, 
                );
    }
    
    $np->add_message(OK,'');
	my ($exit_code, $exit_message) = $np->check_messages();
	$np->nagios_exit($exit_code, $exit_message);
}

sub print_filter_list($$$)
{
	my $np = shift or die;
	my $base_oid  = shift or die;
	my $filters = shift or die;
	# foreach my $item (sort {$filters->{$a} cmp $filters->{$b}} keys %$filters)
	foreach my $item (sort keys %$filters)
	{
		if (!$np->opts->noperfdata) {
			my $filterID  = substr($item, length($base_oid) + 1 , length($item) - length($base_oid) - 1 );
        	$np->add_perfdata(label => "$filters->{$item}|$filterID", 
                value => 1, 
                );
		}

        
    }
}

sub filter_cb($$)
{
	my ($snmp_session, $np, $mode, $base_oid, $total_items, $filters) = @_;
	$np->nagios_die("filter_cb:" . $snmp_session->error()) if (!defined $snmp_session->var_bind_list);
	my $next;
	my $size = keys %{$snmp_session->var_bind_list};
	$total_items += $size;
	foreach my $oid (oid_lex_sort(keys(%{$snmp_session->var_bind_list}))) {
		# print("$oid: " . $snmp_session->var_bind_list->{$oid} . "\n");
		if (!oid_base_match($base_oid, $oid)) {
			$next = undef;
			last;
		}
		$next = $oid; 
		$filters->{$oid} = $snmp_session->var_bind_list->{$oid};
	}
	# If $next is defined we need to send another request 
		# to get more of the table.
	if (defined($next)) {
		if ($total_items < $np->opts->max_item) {
			my $result = $snmp_session->get_bulk_request(-varbindlist => [$next], 
												-maxrepetitions => 5, 
												-callback => [\&filter_cb, $np, $mode, $base_oid, $total_items, $filters]);
			$np->nagios_die("filter_cb:" . $snmp_session->error()) if (!defined $result);
		}
		else {
			save_cached($np, $np->opts->hostname, $mode, $filters);
			my $total_all_items = keys %{$filters};
			my $message = "Total items: " . $total_all_items;
			$message .= ". Maximum number of items/session reach: " . $np->opts->max_item;
			$message .= ". Please re-query to get next items";
			$np->add_message(WARNING,$message);
			print_filter_list($np, $base_oid, $filters);
			my ($exit_code, $exit_message) = $np->check_messages();
			$np->nagios_exit($exit_code, $exit_message);
		}
		
	} else {
		# We are no longer in the table, so print the results.
		# foreach my $oid (oid_lex_sort(keys(%{$filters}))) {
		# 	printf("%s => %s\n", $oid, $filters->{$oid});
		# }	
		save_cached($np, $np->opts->hostname, $mode, $filters);
		my $total_all_items = keys %{$filters};
		my $message = "Total items: " . $total_all_items;
		$np->add_message(OK,$message);
		print_filter_list($np, $base_oid, $filters);
		my ($exit_code, $exit_message) = $np->check_messages();
		$np->nagios_exit($exit_code, $exit_message);
		
	}
}

sub get_filter_list($$$$$)
{
    my $np = shift or die;
	my $snmp_session = shift or die;
	my $mode = shift or die;
	my $nonblocking = shift or die;
    my $base_oid = shift or die;
	my $total_items = 0;
	my $cached_info = get_cached($np, $np->opts->hostname, $mode);
	my $filters = {};
	my $next = $base_oid;
	if (defined $cached_info) {
		$filters = $cached_info;
		foreach my $oid (oid_lex_sort(keys(%{$cached_info}))) {
			if (!oid_base_match($base_oid, $oid)) {
				last;
			}
			$next = $oid; 
		}
	}
	
    my $result = $snmp_session->get_bulk_request(-varbindlist => [$next], 
											 -maxrepetitions => 5, 
											 -callback => [\&filter_cb, $np, $mode, $base_oid, $total_items, $filters]);
	$np->nagios_die("get_filter_list:" . $snmp_session->error()) if (!defined $result);
	snmp_dispatcher();
	$snmp_session->close();
}	

sub get_filterid($$$$)
{
	my $np = shift or die;
	my $snmp_session = shift or die;
	my $filter = shift or die;
    my $oid = shift or die;
	# Get oid index by filter name
    my $result = $snmp_session->get_entries(-columns => [$oid], -maxrepetitions => 10);
	$np->nagios_die('get_filterid: ' . $snmp_session->error()) if !defined $result;

    foreach my $item (keys %$result)
    {
        # print "ifid:$item. name: $result->{$item}\n";
        if ($result->{$item} eq $filter)
        {
            $item =~ s/$oid\.//;
            # print $item;
            return $item;
        }
    }
	
}

sub get_qos_info($$$$)
{
    my $np = shift or die;
	my $snmp_session = shift or die;
    my $filterid = shift or die;
    my $oid_hash = shift or die;
    my @oids = ();
    
	foreach my $item (keys %$oid_hash)
	{
		push @oids, "$oid_hash->{$item}.$filterid";
	}

	my $result = $snmp_session->get_request(-varbindlist => [@oids]);
	$np->nagios_die('get_qos_info: ' . $snmp_session->error()) if (!defined $result);

	my $info = {};

	foreach my $item (keys %$oid_hash)
	{
		$info->{$item} = $result->{"$oid_hash->{$item}.$filterid"};
	}

	return $info;
}

sub get_upload_qos($$$)
{
    my $np = shift or die;
	my $snmp_session = shift or die;
    my $filterid = shift or die;
    my $oids = $OIDS_UPLOAD_QOS;
    # Get Cached Filter Info
    my $cached_info = get_cached($np, $np->opts->hostname, 'upload-' . $filterid);
    my $info = get_qos_info($np, $snmp_session, $filterid, $OIDS_UPLOAD_QOS);
    $info->{time} = time;
    $info->{uploadFilterId} = $filterid;
    save_cached($np, $np->opts->hostname, 'upload-' . $filterid, $info);

    #----------------------------------------
    # Do the Math
    #----------------------------------------
    my ($bps, $pps);

    if (defined $cached_info)
    {
        my $timedelta = $info->{time} - $cached_info->{time};
        if ($timedelta > 0)
        {
            $bps = ($info->{jnxFWCounterByteCount} - $cached_info->{jnxFWCounterByteCount}) * 8 / $timedelta;
            $pps = ($info->{jnxFWCounterPacketCount} - $cached_info->{jnxFWCounterPacketCount}) / $timedelta;
        }
        else
        {
            $bps = $pps = 0;
        }
    }
    else
    {
        $bps = $pps = 0;
    }

    #----------------------------------------
    # Perf data
    #----------------------------------------

    if (!$np->opts->noperfdata)
    {
        $np->add_perfdata(label => "upload_bps", value => int($bps), warning => $np->opts->w_upload_bps, critical => $np->opts->c_upload_bps);
        $np->add_perfdata(label => "upload_pps", value => int($pps), warning => $np->opts->w_upload_pps, critical => $np->opts->c_upload_pps);
    }

    #----------------------------------------
    # Metrics Summary
    #----------------------------------------

    my $metrics;
    
    $metrics = sprintf("$info->{jnxFWCounterDisplayName} upload %s / %s",
        unit_value($bps, 'bps', 1024),
        unit_value($pps, 'pps'),
    );
    
    #----------------------------------------
    # Status Checks
    #----------------------------------------

    my $code;
    my $prefix = "";

    $np->add_message(OK,'');

    if (($code = $np->check_threshold(check => $bps, warning => $np->opts->w_upload_bps, critical => $np->opts->c_upload_bps)) != OK)
    {
        $np->add_message($code, ' [UPLOAD BPS]');
    }
    if (($code = $np->check_threshold(check => $pps, warning => $np->opts->w_upload_pps, critical => $np->opts->c_upload_pps)) != OK)
    {
        
        $np->add_message($code, ' [UPLOAD PPS]');
    }
    
    my ($exit_code, $exit_message) = $np->check_messages();

    $exit_message = $prefix . join(' ', ($exit_message, $metrics));
    $exit_message =~ s/^ *//;

    $np->nagios_exit($exit_code, $exit_message);
}


sub get_download_qos($$$)
{
    my $np = shift or die;
	my $snmp_session = shift or die;
    my $filterid = shift or die;
    my $oids = $OIDS_UPLOAD_QOS;
    # Get Cached Filter Info
    my $cached_info = get_cached($np, $np->opts->hostname, 'download-' . $filterid);
    my $info = get_qos_info($np, $snmp_session, $filterid, $OIDS_DOWNLOAD_QOS);
    $info->{time} = time;
    $info->{downloadFilterId} = $filterid;
    save_cached($np, $np->opts->hostname, 'download-' . $filterid, $info);

    #----------------------------------------
    # Do the Math
    #----------------------------------------
    my ($bps, $pps);

    if (defined $cached_info)
    {
        my $timedelta = $info->{time} - $cached_info->{time};
        if ($timedelta > 0)
        {
            $bps = ($info->{jnxScuStatsBytes} - $cached_info->{jnxScuStatsBytes}) * 8 / $timedelta;
            $pps = ($info->{jnxScuStatsPackets} - $cached_info->{jnxScuStatsPackets}) / $timedelta;
        }
        else
        {
            $bps = $pps = 0;
        }
    }
    else
    {
        $bps = $pps = 0;
    }

    #----------------------------------------
    # Perf data
    #----------------------------------------

    if (!$np->opts->noperfdata)
    {
        $np->add_perfdata(label => "download_bps", value => int($bps), warning => $np->opts->w_download_bps, critical => $np->opts->c_download_bps);
        $np->add_perfdata(label => "download_pps", value => int($pps), warning => $np->opts->w_download_pps, critical => $np->opts->c_download_pps);
    }

    #----------------------------------------
    # Metrics Summary
    #----------------------------------------

    my $metrics;
    
    $metrics = sprintf("$info->{jnxScuStatsClName} download %s / %s",
        unit_value($bps, 'bps', 1024),
        unit_value($pps, 'pps'),
    );
    
    #----------------------------------------
    # Status Checks
    #----------------------------------------

    my $code;
    my $prefix = "";

    $np->add_message(OK,'');

    if (($code = $np->check_threshold(check => $bps, warning => $np->opts->w_download_bps, critical => $np->opts->c_download_bps)) != OK)
    {
        
        $np->add_message($code, ' [DOWNLOAD BPS]');
    }
    if (($code = $np->check_threshold(check => $pps, warning => $np->opts->w_download_pps, critical => $np->opts->c_download_pps)) != OK)
    {
        
        $np->add_message($code, ' [DOWNLOAD PPS]');
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
	shortname => 'JUNIPER-QOS',
	usage => "usage: check_juniper_qos.pl <options> -H <host_address> \n   use --help for more info",
	plugin => 'JUNIPER-QOS',
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
	default => 'list-upload-filter',
);

# Filter params
# $np->add_arg(
# 	spec => 'filter=s',
# 	help => "Filter name",
# );

$np->add_arg(
	spec => 'filter_index=s',
	help => "Filter index",
);

$np->add_arg(
	spec => 'max_item=s',
	help => "Maximum number of items per query",
	default => 500,
);


# Upload Threshold
$np->add_arg(
	spec => 'w_upload_bps=s',
	help => "INTEGER:INTEGER\n   warning threshold for upload qos (bps)\n"
);

$np->add_arg(
	spec => 'c_upload_bps=s',
	help => "INTEGER:INTEGER\n   critical threshold for upload qos (bps)\n"
);

$np->add_arg(
	spec => 'w_upload_pps=s',
	help => "INTEGER:INTEGER\n   warning threshold for upload qos (pps)\n"
);

$np->add_arg(
	spec => 'c_upload_pps=s',
	help => "INTEGER:INTEGER\n   critical threshold for upload qos (pps)\n"
);

# Download Threshold
$np->add_arg(
	spec => 'w_download_bps=s',
	help => "INTEGER:INTEGER\n   warning threshold for download qos (bps)\n"
);

$np->add_arg(
	spec => 'c_download_bps=s',
	help => "INTEGER:INTEGER\n   critical threshold for download qos (bps)\n"
);

$np->add_arg(
	spec => 'w_download_pps=s',
	help => "INTEGER:INTEGER\n   warning threshold for download qos (pps)\n"
);

$np->add_arg(
	spec => 'c_download_pps=s',
	help => "INTEGER:INTEGER\n   critical threshold for download qos (pps)\n"
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
# Cache Directory
#----------------------------------------

if (! -w $np->opts->datadir)
{
	$np->nagios_die("Unable to write to data directory" . $np->opts->datadir);
}

#----------------------------------------
# List mode
#----------------------------------------
if (defined $np->opts->modes)
{
	print "Mode list:\n";
	print "list-upload-filter: list upload filters \n";
    print "list-download-filter: list download filters \n";
    print "upload: get upload bps and pps\n";
    print "download: get download bps and pps\n";
	$np->nagios_exit(OK,'');
}


#----------------------------------------
# Plugin mode
#----------------------------------------
if ($np->opts->mode eq "list-upload-filter")
{
    # my $str = oid_to_ascii('.12.73.80.84.45.84.101.115.116.49.45.85.80.20.49.48.77.45.73.80.84.45.84.101.115.116.49.45.73.71.87.45.85.80.3');
    # print($str);
	get_filter_list($np, $snmp_session, "list-upload", $nonblocking, $OIDS_UPLOAD_QOS->{jnxFWCounterDisplayName});
}
elsif ($np->opts->mode eq "list-download-filter")
{
    # my $str = oid_to_ascii('.588.2.3.73.88.80');
    # print($str);
	get_filter_list($np, $snmp_session, "list-download", $nonblocking, $OIDS_DOWNLOAD_QOS->{jnxScuStatsClName});
}
elsif ($np->opts->mode eq "upload")
{
    get_upload_qos($np, $snmp_session, $np->opts->filter_index);
}
elsif ($np->opts->mode eq "download")
{
    get_download_qos($np, $snmp_session, $np->opts->filter_index);
}





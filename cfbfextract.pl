#!/usr/bin/perl -wT

use warnings;
use strict;

use Fcntl qw / O_RDONLY O_BINARY SEEK_SET SEEK_CUR /;
use feature qw / :5.10 /;

use constant {
	STGTY_INVALID => 0,
	STGTY_STORAGE => 1,
	STGTY_STREAM => 2,
	STGTY_LOCKBYTES => 3,
	STGTY_PROPERTY => 4,
	STGTY_ROOT => 5,
	
	DE_RED => 0,
	DE_BLACK => 1,
	
	MAXREGSECT => 0xFFFFFFFA,
	DIFSECT => 0xFFFFFFFC,
	FATSECT => 0xFFFFFFFD,
	ENDOFCHAIN => 0xFFFFFFFE,
	FREESECT => 0xFFFFFFFF,
	MAXREGSID => 0xFFFFFFF,
	NOSTREAM => 0xFFFFFFFF,
	
	HEADER_SIZE => 512,
	DIRENT_SIZE => 128,
};

my @STGTY = ( "STGTY_INVALID", "STGTY_STORAGE", "STGTY_STREAM", "STGTY_LOCKBYTES", "STGTY_PROPERTY", "STGTY_ROOT" );
my @DECOLOR = ( "DE_RED", "DE_BLACK" );

binmode STDOUT, ":utf8";

sub unpackToHash {
	my ($buff, @format) = @_;
	
	# catenate the pack types into a string and unpack
	my $unpack_format = join "", map { $_->{type} } @format;
	my @vals = unpack($unpack_format, $buff);
		
	# set values in result hash based on values read
	# TODO: parse unpack type string and grab actual number of elements implied (ie: L109 -> 109 elements, a16 -> 1 element)
	my %result = map { $format[$_]->{name} => $vals[$_] } (0 .. $#format - 1);
	#print "$_ => " . $result{$_} . "\n" for (keys(%result));
		
	
	# TODO: for now just set the last value to the the array of the remaining values
	my @rem = @vals[$#format .. $#vals];
	$result{$format[$#format]->{name}} = \@vals[$#format .. $#vals];
	#printf "header: $#format vals: $#vals rem: $#rem  dif:" . scalar @{$result{$format[$#format]->{name}}} . "\n";
	
	return %result;
}


sub printTable {
	my ($values, $format) = @_;
	
	sub pp;
	sub pp {
		my ($v) = shift;
		my ($size) = shift || 4;
		return "UNDEF" unless defined($v);
		
		if (ref($v) eq "") {
			if ($v =~ /^\d+$/) 	{ 
				my $nibbles = $size * 2;
				return sprintf("0x%0${nibbles}X (%d)", $v, $v);

			} else { 
				return sprintf("\\x%s", unpack("H*", $v)); 
			}
			
		} elsif (ref($v) eq "ARRAY") {
			return join(",", map { pp($_) } @$v);
			
		} elsif (ref($v) eq "HASH") {
			my $hash = $v;
			return join ",", map({"$_=>".pp($hash->{$v})} keys(%$hash));
		}
	};
			
	foreach (@$format) {
		my $descr = $_->{name} . " (" . $_->{type} . ")";
		my $val = $values->{$_->{name}};
				
		printf "%-22s = %s (%s)\n", $descr, pp($val, $_->{size}), $_->{description}->($val);	
	}
}

sub descrStr {
	my ($descr) = @_;
	return sub {
		return $descr;
	};
}


my @header_format = (
	{ type => 'C0a8', 	name => 'abSig', 		size => 8, 	description => descrStr("{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1} for current version") },
	{ type => 'C0a16', 	name => 'clsid',		size => 16,	description => descrStr("reserved must be zero (WriteClassStg/GetClassFile uses root directory class id)") },
	{ type => 'S<', 	name => 'minorVersion', size => 2, 	description => descrStr("minor version of the format: 33 is written by reference implementation") },
	{ type => 'S<', 	name => 'dllVersion', 	size => 2, 	description => descrStr("major version of the dll/format: 3 for 512-byte sectors, 4 for 4 KB sectors") },
	{ type => 'S<', 	name => 'byteOrder',	size => 2, 	description => descrStr("0xFFFE: indicates Intel byte-ordering") },
	{ type => 'S<', 	name => 'sectorShift',	size => 2, 	description => descrStr("size of sectors in power-of-two; typically 9 indicating 512-byte sectors") },
	{ type => 'S<', 	name => 'miniSectorShift', size => 2, description => descrStr("size of mini-sectors in power-of-two; typically 6 indicating 64-byte mini-sectors") },
	{ type => 'S<', 	name => 'sReserved', 	size => 2, 	description => descrStr("reserved, must be zero") },
	{ type => 'L<', 	name => 'lReserved', 	size => 4, 	description => descrStr("reserved, must be zero") },
	{ type => 'L<', 	name => 'numSectDir',	size => 4, 	description => descrStr("must be zero for 512-byte sectors, number of SECTs in directory chain for 4 KB sectors") },
	{ type => 'L<', 	name => 'numSectFat',	size => 4, 	description => descrStr("number of SECTs in the FAT chain") },
	{ type => 'L<', 	name => 'sectDirStart',	size => 4, 	description => descrStr("first SECT in the directory chain") },
	{ type => 'L<', 	name => 'signature',	size => 4, 	description => descrStr("signature used for transactions; must be zero.") },
	{ type => 'L<', 	name => 'miniSectorCutoff', size => 4, 	description => descrStr("maximum size for a mini stream; typically 4096 bytes") },
	{ type => 'L<', 	name => 'sectMiniFatStart', size => 4, 	description => descrStr("first SECT in the MiniFAT chain") },
	{ type => 'L<', 	name => 'numSectMiniFat', size => 4, 	description => descrStr("number of SECTs in the MiniFAT chain") },
	{ type => 'L<', 	name => 'sectDifStart', size => 4, 	description => descrStr("first SECT in the DIFAT chain") },
	{ type => 'L<', 	name => 'sectDif', 		size => 4, 	description => descrStr("number of SECTs in the DIFAT chain") },
	{ type => 'L<109', 	name => 'sectFat', 		size => 436,description => descrStr("the SECTs of first 109 FAT sectors") },
);

my @directory_format = (
	{ type => 'C64', 	name => 'name', 	size => 64, description => descrStr("64 bytes. The element name in Unicode, padded with zeros to fill this byte array.") },
	{ type => 'S<', 	name => 'nameLen', 	size => 2, description => descrStr("Length of the Element name in bytes, including the Unicode NULL") },
	{ type => 'C', 		name => 'objType', 	size => 1, description => sub { "ObjType: @STGTY[$_[0]] ($_[0])"; } },
	{ type => 'C', 		name => 'flags', 	size => 1, description => sub { "Node Color: @DECOLOR[$_[0]] ($_[0])"; } },
	{ type => 'L<', 	name => 'leftSib', 	size => 4, description => descrStr("SID of the left-sibling of this entry in the directory tree") },
	{ type => 'L<', 	name => 'rightSib', size => 4, description => descrStr("SID of the right-sibling of this entry in the directory tree") },
	{ type => 'L<', 	name => 'child', 	size => 4, description => descrStr("SID of the child acting as the root of all the children of this element (if objType=STGTY_STORAGE or STGTY_ROOT)") },
	{ type => 'C0a16', 	name => 'clsId', 	size => 16, description => descrStr("CLSID of this storage (if objType=STGTY_STORAGE or STGTY_ROOT)") },
	{ type => 'L<', 	name => 'userFlags',size => 4, description => descrStr("User flags of this storage (if objType=STGTY_STORAGE or STGTY_ROOT)") },
	{ type => 'L<', 	name => 'createTime', size => 4, description => descrStr("Create time-stamp(low) (if objType=STGTY_STORAGE)") },
	{ type => 'L<', 	name => 'createTime', size => 4, description => descrStr("Create time-stamp(high) (if objType=STGTY_STORAGE)") },
	{ type => 'L<', 	name => 'modifyTime', size => 4, description => descrStr("Modify time-stamp(low) (if objType=STGTY_STORAGE)") },
	{ type => 'L<', 	name => 'modifyTime', size => 4, description => descrStr("Modify time-stamp(high) (if objType=STGTY_STORAGE)") },
	{ type => 'L<', 	name => 'sectStart',size => 4, description => descrStr("starting SECT of the stream (if objType=STGTY_STREAM)") },
	{ type => 'L<', 	name => 'sizeLow', 	size => 4, description => descrStr("size of stream in bytes (objType=STGTY_STREAM)") },
	{ type => 'S<', 	name => 'sizeHigh', size => 2, description => descrStr("must be zero for 512-byte sectors, high part of 64-bit size for 4 KB sectors") },
	{ type => 'S<',		name => 'padding', 	size => 2, description => descrStr("padding") },
);

sub systell {
	my ($fd) = @_;
	return sysseek($fd, 0, SEEK_CUR);	
}

sub readfully {
	my ($fd, $len) = (@_);
	my $buff = "";
	while ($len > 0) {
		my $br = sysread($fd, $buff, $len - length($buff), length($buff));
		last if ($br <= 0);
		$len -= $br;
	}
	return $buff;
}

my $infile = $ARGV[0];
my ($infd, $buff);

sysopen($infd, $infile, O_RDONLY | O_BINARY) or die("unable to open:$infd: $!");					    

my %header = unpackToHash(readfully($infd, HEADER_SIZE), @header_format);
printTable(\%header, \@header_format);

my $sectorSize = 1 << $header{sectorShift};

my %rootdir = unpackToHash(readfully($infd, DIRENT_SIZE), @directory_format);
print "*" x 20 . "\nRoot Directory entry:\n";
printTable(\%rootdir, \@directory_format);

my @rootdirEntries = ();
for (1..3) {
	push @rootdirEntries, \%{unpackToHash(readfully($infd, DIRENT_SIZE), @directory_format)};
	print "Dir entry:";
	printTable(@rootdirEntries, \@directory_format);	
}


for my $fat (@{$header{sectFat}}) {
	last if ($fat == NOSTREAM);
	
	print "*" x 20 . "\n";
	print "FAT @ $fat\n";
	
	my ($fatOffset) = ($sectorSize * ($fat + 1));
	if (sysseek($infd, $fatOffset, SEEK_SET) != $fatOffset) {
		die("unable to seek to fat sector:$fat at offset:$fatOffset");
	}
	
	
}


close($infd);



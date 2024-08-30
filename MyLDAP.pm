package MyLDAP;
use strict;
use Net::LDAP;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );

use Data::Dumper;
use Encode;
use LWP::UserAgent;
use XML::Simple;
use JSON;
use MIME::Base64;
use Try::Tiny;
use Socket;
use utf8;

use Exporter;

#binmode(STDIN, ":utf8");
#binmode(STDOUT, ":utf8");
#binmode(STDERR, ":utf8");

our @ISA= qw( Exporter );
our @EXPORT = qw( myldapsearch );
our @EXPORT_OK = qw( myldapsearch );

sub long2ip 
{
    return inet_ntoa(pack("N*", shift));
}

my @utf_attrs=qw/dn cn company description displayName distinguishedName givenName info l ipPhone msRTCSIP-PrimaryUserAddress name physicalDeliveryOfficeName sAMAccountName sn title userPrincipalName/;
my @bin_attrs=qw/objectGUID objectSid logonHours userParameters userCertificate/;
my @filetime_attrs=qw/lockoutTime pwdLastSet accountExpires badPasswordTime lastLogon lastLogonTimestamp/;

my %UAC = (
"SCRIPT" => 0x0001,
"ACCOUNTDISABLE" => 0x0002,
"HOMEDIR_REQUIRED" => 0x0008,
"LOCKOUT" => 0x0010,
"PASSWD_NOTREQD" => 0x0020,
"PASSWD_CANT_CHANGE" => 0x0040,
"ENCRYPTED_TEXT_PWD_ALLOWED" => 0x0080,
"TEMP_DUPLICATE_ACCOUNT" => 0x0100,
"NORMAL_ACCOUNT" => 0x0200,
"INTERDOMAIN_TRUST_ACCOUNT" => 0x0800,
"WORKSTATION_TRUST_ACCOUNT" => 0x1000,
"SERVER_TRUST_ACCOUNT" => 0x2000,
"DONT_EXPIRE_PASSWORD" => 0x10000,
"MNS_LOGON_ACCOUNT" => 0x20000,
"SMARTCARD_REQUIRED" => 0x40000,
"TRUSTED_FOR_DELEGATION" => 0x80000,
"NOT_DELEGATED" => 0x100000,
"USE_DES_KEY_ONLY" => 0x200000,
"DONT_REQ_PREAUTH" => 0x400000,
"PASSWORD_EXPIRED" => 0x800000,
"TRUSTED_TO_AUTH_FOR_DELEGATION" => 0x1000000,
"PARTIAL_SECRETS_ACCOUNT" => 0x04000000
);


sub decode_attr {
  my $a=shift;
  my $val=shift;

  if(scalar(grep { $a eq $_ } @utf_attrs)) {
    return decode("UTF-8", $val);
  } elsif(scalar(grep { $a eq $_ } @filetime_attrs)) {
    use integer;
    return scalar(localtime(($val-116444736000000000)/10000000));
    no integer;
  } elsif(scalar(grep { $a eq $_ } @bin_attrs)) {
    return "BASE64;".encode_base64($val, '');
  } elsif($a eq "userAccountControl") {
    use integer;
    my @uac_bits;
    foreach my $key (keys(%UAC)) {
      if(($val & $UAC{$key}) != 0) {
        push(@uac_bits, $key);
      };
    };
    return("$val: ".sprintf("0x%X: ", $val).join(",", @uac_bits));
    no integer;
  } elsif($val =~ /[^[:print:]]/) {
    my $ret;
    try {
      $ret=decode("UTF-8", $val, Encode::FB_CROAK);
    } catch {
      $ret="BASE64;".encode_base64($val, '');
    };
    return $ret;
  } elsif($a eq 'msRADIUSFramedIPAddress') {
    return $val." (".long2ip($val).")";
  };
  return $val;
};

sub myldapsearch {

  my %args = %{shift()};

  my $LDAP_HOST = $args{"host"};
  my $LDAP_PROTO = $args{"proto"};
  my $LDAP_USER = $args{"user"};
  my $LDAP_PASS = $args{"pass"};
  my $opt_s = $args{"opt_s"};
  my $opt_b = $args{"opt_b"};
  my $filter = $args{"filter"};


  our $ldap=Net::LDAP->new($LDAP_HOST,scheme=>$LDAP_PROTO) or die "$@";
  $ldap->start_tls(verify=>'none') or die "$@";
  $ldap->bind($LDAP_USER, password => $LDAP_PASS) or die "$@";

  my $page = Net::LDAP::Control::Paged->new( size => 100 );

  my $cookie;

  my @argv_attrs = @{$args{"attrs"}};

  while(1) {
    my $lres;

    $lres=$ldap->search(
      base => $opt_b,
      attrs => \@argv_attrs,
      scope => $opt_s,
      filter => $filter,
      control  => [ $page ]
    );

    if($lres->code) {
      die $lres->error;
    };

    foreach my $l ($lres->entries) {
      my $dn=decode("UTF-8", $l->dn());
      #my @attrs=sort($l->attributes( nooptions => 1) );
      my @attrs=sort($l->attributes() );
      print("$dn\n");
      foreach my $a (@attrs) {
        my @values=$l->get_value($a);
        if(!scalar(@values)) {
          print("\t$a:\tEMPTY LIST\n");
        } else {
          foreach my $val (@values) {
            my $decoded=decode_attr($a, $val);
            print("\t$a:\t$decoded\n");
          };
        };
      };
    };

    my($resp)  = $lres->control( LDAP_CONTROL_PAGED )  or last;
    $cookie    = $resp->cookie;

    # Only continue if cookie is nonempty (= we're not done)
    last  if (!defined($cookie) || !length($cookie));

    # Set cookie in paged control
    $page->cookie($cookie);
  };
};

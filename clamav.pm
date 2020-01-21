#
# Author: Giovanni Bechis <gbechis@apache.org>
# Copyright 2019 Giovanni Bechis
#
# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#

=head1 NAME

Mail::SpamAssassin::Plugin::Clamav - check email body using Clamav antivirus

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::Clamav

  ifplugin Mail::SpamAssassin::Plugin::Clamav
    clamd_sock 3310
    full AV_CLAMAV eval:check_clamav()
    describe AV_CLAMAV Clamav AntiVirus detected a virus

    full AV_CLAMAV_S eval:check_clamav_sanesecurity()
    describe AV_CLAMAV_S Clamav AntiVirus detected a virus in SaneSecurity signatures
  endif

=head1 DESCRIPTION

This plugin checks emails using Clamav antivirus.
If the parameter "OFFICIAL" is passed to C<check_clamav>
only official signatures are checked.

=cut

package Mail::SpamAssassin::Plugin::Clamav;

use strict;
use warnings;
use re 'taint';

my $VERSION = 0.1;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(untaint_var);

our @ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_CLAMAV => eval { require File::Scan::ClamAV; };

BEGIN
{
    eval{
      import File::Scan::ClamAV
    };
}

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Clamav: @_"); }

sub new {
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_clamav");
    $self->register_eval_rule("check_clamav_sanesecurity");

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;

=over 4

=item clamd_sock (default: 3310)

Clamd socket to connect to, by default tcp/ip connection on port 3310 is used.

=back

=cut

    push(@cmds, {
        setting => 'clamd_sock',
        default => '3310',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        }
    );
    $conf->{parser}->register_commands(\@cmds);
}

sub check_clamav {
  my ($self,$pms,$body,$name) = @_;

  my $rulename = $pms->get_current_eval_rule_name();

  _check_clamav(@_) unless exists $pms->{clamav_virus};

  $name //= "ALL";

  return 0 if not defined $pms->{clamav_virus};
  dbg("found virus $pms->{clamav_virus} $name");
  if($pms->{clamav_virus} =~ /^$name.*UNOFFICIAL$/) {
    # include the virus name in SpamAssassin's report
    $pms->test_log($pms->{clamav_virus});
    $pms->got_hit($rulename, "", ruletype => 'eval');

    # add informative tag and header
    $pms->{msg}->put_metadata('X-Spam-Virus', $pms->{clamav_virus});
    return 1;
  } elsif(($name eq "OFFICIAL") and ($pms->{clamav_virus} !~ /UNOFFICIAL$/)) {
    # report only viruses detected in official signatures
    $pms->test_log($pms->{clamav_virus});
    $pms->got_hit($rulename, "", ruletype => 'eval');

    # add informative tag and header
    $pms->{msg}->put_metadata('X-Spam-Virus', $pms->{clamav_virus});
    return 1;
  } elsif($name eq "ALL") {
    # report viruses detected in all
    $pms->test_log($pms->{clamav_virus});
    $pms->got_hit($rulename, "", ruletype => 'eval');

    # add informative tag and header
    $pms->{msg}->put_metadata('X-Spam-Virus', $pms->{clamav_virus});
    return 1;
  }
  return 0;
}

sub check_clamav_sanesecurity {
  my ($self,$pms,$body,$name) = @_;
  return $self->check_clamav("SecuriteInfo");
}

sub _check_clamav {
  my($self, $pms, $fulltext) = @_;

  my $isspam = 0;

  my $conf = $self->{main}->{registryboundaries}->{conf};

  if (!HAS_CLAMAV) {
    warn "check_clamav not supported, required module File::Scan::Clamav missing\n";
    return 0;
  }

  dbg("File::Scan::ClamAV connecting on socket $conf->{clamd_sock}");
  my $clamav = new File::Scan::ClamAV(port => untaint_var($conf->{clamd_sock}));
  if($clamav->ping) {
    my($code, $virus) = $clamav->streamscan(${$fulltext});

    if (!$code) {
      my $error = $clamav->errstr();
      dbg("Clamd error: $error");
    } elsif ($code eq 'OK') {
      # No virus found
    } elsif ($code eq 'FOUND') {
      $isspam = 1;

      $pms->{clamav_virus} = $virus;
    } else {
      dbg("Error (Unknown return code from Clamav: $code");
    }
  } else {
    dbg("Cannot connect to Clamav on socket $conf->{clamd_sock}");
  }
  return $isspam;
}

1;

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
  endif

=head1 DESCRIPTION

This plugin checks emails using Clamav antivirus.

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

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;
    push(@cmds, {
        setting => 'clamd_sock',
        default => '3310',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        }
    );
    $conf->{parser}->register_commands(\@cmds);
}

sub check_clamav {
  my($self, $pms, $fulltext) = @_;

  my $isspam = 0;
  my $header = "";

  my $conf = $self->{main}->{registryboundaries}->{conf};
  my $rulename = $pms->get_current_eval_rule_name();

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
      $header = "Error ($error)";
    } elsif ($code eq 'OK') {
      $header = "No";
    } elsif ($code eq 'FOUND') {
      $header = "Yes ($virus)";
      $isspam = 1;

      # include the virus name in SpamAssassin's report
      dbg("HIT! virus $virus found");
      $pms->test_log($virus);
      $pms->got_hit($rulename, "", ruletype => 'eval');

      # add informative tag and header
      $pms->{msg}->put_metadata('X-Spam-Virus',$header);
    } else {
      $header = "Error (Unknown return code from Clamav: $code)";
    }
  } else {
    dbg("Cannot connect to Clamav on socket $conf->{clamd_sock}");
  }
  return $isspam;
}

1;

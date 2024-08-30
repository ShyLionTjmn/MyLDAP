Edit xldap to change credentials or add you way to pass them.

Put MyLDAP.pm to perl modules dir, like:
  sudo cp MyLDAP.pm /etc/perl/

Put xldap to one of $PATH dir
  sudo cp xldap /usr/local/bin/

usage example: xldap 'CN=Joe Doe' samaccountname useraccountcontrol

# encoding: utf-8
# copyright: 2018, The Authors

control "Password_Creation_Requirement_Parameters_Using_pam_pwquality" do
  title "Set Password Creation Requirement Parameters Using pam_pwquality"
  desc  "
    The pam_pwquality module checks of the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the pam_pwquality.so options.

    * try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.
    * retry=3- Allow 3 tries before sending back a failure.
    The following options are set in the /etc/security/pwquality.conf file:

    * minlen=8 - password must be 8 characters or more
    * dcredit=-1 - provide at least 1 digit
    * ucredit=-1 - provide at least one uppercase character
    * ocredit=-1 - provide at least one special character
    * lcredit=-1 - provide at least one lowercase character
    The setting shown above is one possible policy. Alter these values to conform to your own organization's password policies.

    Rationale: Strong passwords protect systems from being hacked through brute force methods.
  "
  impact 1.0
  describe file('/etc/security/opasswd') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
  end

  describe file('/var/log/faillog') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
  end

  describe file('/var/log/tallylog') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
  end

  describe file("/etc/login.defs") do
    its('content') { should match /^PASS_MIN_LEN.*[8-9]|[1-9][0-9]$/ }
    its('content') { should match /^PASS_MAX_DAYS.*90$/ }
    its('content') { should match /^PASS_MIN_DAYS.*1$/ }
    its('content') { should match /^PASS_WARN_AGE.*14$/ }

  end




  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:required|requisite)\s+pam_pwquality.so\s+(?:\S+\s+)*try_first_pass(?:\s+\S+)*\s*$/) }
  end
  describe file("/etc/pam.d/system-auth") do
    its("content") { should match(/^\s*password\s+(?:required|requisite)\s+pam_pwquality.so\s+(?:\S+\s+)*retry=[123](?:\s+\S+)*\s*$/) }
  end

  describe file("/etc/pam.d/system-auth") do
      its('content') { should match /^auth.*required.*pam_tally2.so.*onerr=fail.*deny=5$/ }
      its('content') { should match /^auth.*required.*pam_faildelay.so.*delay=2000000$/ }
      its('content') { should match /^password.*requisite.*pam_pwhistory.so.*remember=5.*use_authtok$/ }
  end





  describe parse_config_file("/etc/security/pwquality.conf") do
    its('minlen'){should cmp >=8}
    its('minclass'){should eq '1'}
    its('maxrepeat'){should eq '2'}
    its('dcredit'){should cmp <=-1}
    its('ucredit'){should cmp <=-1}
    its('ocredit'){should cmp <=-1}
    its('lcredit'){should cmp <=-1}
  end

  describe file("/etc/pam.d/passwd") do
    its('content') { should match /password required pam_pwquality.so retry=3/ }
  end






  end

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
      its('content') { should match /^auth.*required.*pam_tally2.so.*onerr=fail.*deny=5$/ }
    #  its('content') { should match /^$/ }
      its('content') { should match /^auth.*sufficient.*pam_fprintd.so$/ }
      its('content') { should match /^auth.*requisite.*pam_succeed_if.so.*uid.*>=.*500.*quiet$/ }
      its('content') { should match /^auth.*sufficient.*pam_unix.so.*[^a-zA-Z]try_first_pass$/ }
      its('content') { should match /^account.*sufficient.*pam_localuser.so$/ }
      its('content') { should match /^account.*sufficient.*pam_succeed_if.so.*uid.*<.*500.*quiet$/ }
      its('content') { should match /^account.*required.*pam_permit.so$/ }
      its('content') { should match /^password.*requisite .*pam_cracklib.so.*try_first_pass.*retry=3.*type=.*minlen=14.*lcredit=-1.*ucredit=-1.*ocredit=-1.*dcredit=-1$/ }    
      its('content') { should match /^password.*sufficient.*pam_unix.so.*sha512.*shadow.*nullok.*try_first_pass.*use_authtok.*remember=8$/ }
  end

  describe file("/etc/pam.d/password-auth") do
      its('content') { should match /^auth.*required.*pam_tally2.so.*onerr=fail.*deny=5$/ }
    #  its('content') { should match /^$/ }
      its('content') { should match /^auth.*requisite.*pam_succeed_if.so.*uid.*>=.*500.*quiet$/ }
      its('content') { should match /^auth.*sufficient.*pam_unix.so.*[^a-zA-Z]try_first_pass$/ }
      its('content') { should match /^account.*sufficient.*pam_localuser.so$/ }
      its('content') { should match /^account.*sufficient.*pam_succeed_if.so.*uid.*<.*500.*quiet$/ }
      its('content') { should match /^account.*required.*pam_permit.so$/ }
      its('content') { should match /^password.*requisite .*pam_cracklib.so.*try_first_pass.*retry=3.*type=.*minlen=14.*lcredit=-1.*ucredit=-1.*ocredit=-1.*dcredit=-1$/ }    
      its('content') { should match /^password.*sufficient.*pam_unix.so.*sha512.*shadow.*nullok.*try_first_pass.*use_authtok.*remember=8$/ }
  end








  end

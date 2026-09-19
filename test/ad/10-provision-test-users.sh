#!/bin/sh
# Runs inside the smblds container (mounted at /entrypoint.d) before Samba
# starts, so it works directly against the local sam.ldb.
# Creates the accounts that test/exldap_test.exs expects:
#   test123  cn=test123, givenName=Test, sn=123, enabled, in two groups,
#            with badPasswordTime seeded (Samba does not set it on failed binds
#            while lockout is disabled, and one test filters on it)
#   test456  a second "test*" account so substring searches return >1 result
#   pwchange account used by the change_password tests
set -e

if samba-tool user show test123 >/dev/null 2>&1; then
  echo "Test users already provisioned"
  exit 0
fi

BASE="DC=samdom,DC=example,DC=com"
SAM="/var/lib/samba/private/sam.ldb"

# Weak password policy so the password-change tests can reuse simple passwords.
samba-tool domain passwordsettings set --complexity=off --min-pwd-length=0 \
  --min-pwd-age=0 --max-pwd-age=0 --history-length=0

samba-tool ou create "OU=Accounts,${BASE}"

# No --given-name/--surname here: samba-tool would then build the CN from them,
# and the tests need CN to equal the account name.
for user in test123 test456 pwchange; do
  samba-tool user create "$user" Passw0rd --userou="OU=Accounts"
  samba-tool user setexpiry "$user" --noexpiry
done

ldbmodify -H "$SAM" <<LDIF
dn: CN=test123,OU=Accounts,${BASE}
changetype: modify
replace: givenName
givenName: Test
-
replace: sn
sn: 123
-
replace: displayName
displayName: Test 123
-
replace: badPasswordTime
badPasswordTime: 133000000000000000

dn: CN=test456,OU=Accounts,${BASE}
changetype: modify
replace: givenName
givenName: Test
-
replace: sn
sn: 456
LDIF

samba-tool group add "Exldap Group One"
samba-tool group add "Exldap Group Two"
samba-tool group addmembers "Exldap Group One" test123
samba-tool group addmembers "Exldap Group Two" test123

echo "Test users provisioned"

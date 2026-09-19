# The integration tests in exldap_test.exs need a directory, see docker-compose.yml.
# Tests tagged :real_ad exercise behaviour Samba AD does not implement.
ExUnit.start(exclude: [:real_ad])

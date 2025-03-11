# Manual test cases for anaconda-auth

## CASE: Default configuration will pull packages from repo.anaconda.com/pkgs/main
#
# GIVEN:
# - A base Miniconda or Anaconda installation
# - No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)
# WHEN:
# - run: conda search flask
# THEN:
# - The channel for all the packages should be "pkgs/main"


# CASE: Legacy install with conda-token
#       This checks that the token can be installed and used via the legacy method.
#
# GIVEN:
# - A base Miniconda or Anaconda installation
# - No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)
# WHEN:
# - run: conda token set <TOKEN>
# - Follow prompts, accepting everything
# - run: conda search flask
# THEN:
# - The channel for all the packages should be "repo/main"


# CASE: New install with manually-provisioned token
#
# GIVEN:
# - A base Miniconda or Anaconda installation
# - No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)
# WHEN:
# - run: anaconda token install --org <ORG_NAME> <TOKEN>
# - Follow prompts, accepting everything
# - run: conda search flask
# THEN:
# - The channel for all the packages should be "repo/main"


# CASE: New interactive token grant flow for a user with a Business subscription
#
# GIVEN:
# - A base Miniconda or Anaconda installation
# - No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)
# - User belongs to an organization with a Business subscription
# WHEN:
# - Run: anaconda token install
# - Follow prompts, accepting everything
# - run: conda search flask
# THEN:
# - The channel for all the packages should be "repo/main"






































# CASE: Reset default channels
#
# GIVEN:
# - The result of Normal token grant flow
# WHEN:
# - conda config --remove-key default_channels
# - $TEST_COMMAND is run
# THEN:
# - The channel for all the packages should be "pkgs/main"


# CASE: Remove all plugin and default channels configuration
#
# GIVEN:
# - The result of Normal token grant flow
# WHEN:
# - conda config --remove-key default_channels
# - conda config --remove-key channel_settings
# THEN:
# - The .condarc file should be back to its original state


# CASE: anaconda auth from anaconda-client still works
#
# GIVEN:
# - anaconda-auth is installed alongside anaconda-client
# WHEN:
# - anaconda org auth -h
# - anaconda auth --info
# THEN:
# - Command should not fail, should delegate to anaconda-client
# - If not logged in, prompt to login to anaconda.org
# - Should print auth token info













# [ "${TST_LOGIN}" != "" ] || read -r -p "Anaconda login: " TST_LOGIN
# [ "${TST_PASSWORD}" != "" ] || read -r -s -p "Anaconda password: " TST_PASSWORD
# echo

# echo -e "/?\\\\ Checking current anaconda-client version:\\n"
# ${TST_CMD} --version
# echo
#
# echo -e "/?\\\\ Checking config:\\n"
#
# ${TST_CMD} config --files 1>/dev/null 2>&1 || (echo -e "\\n\\n/!\\\\ Listing of configuration files test failed.\\n" && exit 1)
# ${TST_CMD} config --show 1>/dev/null 2>&1 || (echo -e "\\n\\n/!\\\\ Configuration presentation test failed.\\n" && exit 1)
#
# echo -e "/?\\\\ Login:\\n"
# echo -e "spawn ${TST_CMD} login\\nexpect {\\n  \"Username: \" {\\n    send -- \"${TST_LOGIN}\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  \"Password: \" {\\n    send -- \"${TST_PASSWORD}\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  \"Password: \" {\\n    send_user \"\\\\nInvalid username/password.\"\\n    exit 67\\n  }\\n  \"Would you like to continue \" {\\n    send -- \"y\\\\r\"\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Login test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Upload package:\\n"
# ${TST_CMD} upload ./data/conda_gc_test-1.2.1-3.tar.bz2 || (echo -e "\\n\\n/!\\\\ Upload package test failed.\\n" && exit 1)
# echo
#
# ${TST_CMD} upload ./data/bcj-cffi-0.5.1-py310h295c915_0.tar.bz2 || (echo -e "\\n\\n/!\\\\ Upload package test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Update package:\\n"
# ${TST_CMD} update "${TST_LOGIN}/conda_gc_test" ./data/conda_gc_test_metadata.json || (echo -e "\\n\\n/!\\\\ Update package test failed.\\n" && exit 1)
# echo
#
# ${TST_CMD} update "${TST_LOGIN}/bcj-cffi" ./data/conda_gc_test_metadata.json || (echo -e "\\n\\n/!\\\\ Update package test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Download package:\\n"
# rm -rf pkg_tmp
# mkdir -p pkg_tmp/noarch pkg_tmp/linux-64
# ${TST_CMD} download "${TST_LOGIN}/conda_gc_test" -o pkg_tmp || (echo -e "\\n\\n/!\\\\ Download package test failed.\\n" && exit 1)
# [ "$(find pkg_tmp -name conda_gc_test-1.2.1-3.tar.bz2 | wc -l)" = 1 ] || (echo -e "\\n\\n/!\\\\ Download package test failed.\\n" && exit 1)
# rm -rf pkg_tmp
# echo
#
# rm -rf pkg_tmp
# mkdir -p pkg_tmp/noarch pkg_tmp/linux-64
# ${TST_CMD} download "${TST_LOGIN}/bcj-cffi" -o pkg_tmp || (echo -e "\\n\\n/!\\\\ Download package test failed.\\n" && exit 1)
# [ "$(find pkg_tmp -name bcj-cffi-0.5.1-py310h295c915_0.tar.bz2 | wc -l)" = 1 ] || (echo -e "\\n\\n/!\\\\ Download package test failed.\\n" && exit 1)
# rm -rf pkg_tmp
# echo
#
# echo -e "/?\\\\ Remove package:\\n"
# echo -e "spawn ${TST_CMD} remove \"${TST_LOGIN}/conda_gc_test\"\\nexpect {\\n  \"Are you sure you want to remove the package \" {\\n    send -- \"y\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Remove package test failed.\\n" && exit 1)
# echo
#
# echo -e "spawn ${TST_CMD} remove \"${TST_LOGIN}/bcj-cffi\"\\nexpect {\\n  \"Are you sure you want to remove the package \" {\\n    send -- \"y\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Remove package test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Upload notebook:\\n"
# ${TST_CMD} upload ./data/hello_binstar.ipynb || (echo -e "\\n\\n/!\\\\ Upload notebook test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Download notebook:\\n"
# rm -rf nbk_tmp
# mkdir -p nbk_tmp
# ${TST_CMD} download "${TST_LOGIN}/hello_binstar" -o nbk_tmp || (echo -e "\\n\\n/!\\\\ Download notebook test failed.\\n" && exit 1)
# [ "$(find nbk_tmp -name hello_binstar.ipynb | wc -l)" = 1 ] || (echo -e "\\n\\n/!\\\\ Download notebook test failed.\\n" && exit 1)
# rm -rf nbk_tmp
# echo
#
# echo -e "/?\\\\ Remove notebook:\\n"
# echo -e "spawn ${TST_CMD} remove \"${TST_LOGIN}/hello_binstar\"\\nexpect {\\n  \"Are you sure you want to remove the package \" {\\n    send -- \"y\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Remove notebook test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Upload environment:\\n"
# ${TST_CMD} upload ./data/test_env.yml || (echo -e "\\n\\n/!\\\\ Upload environment test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Download environment:\\n"
# rm -rf env_tmp
# mkdir -p env_tmp
# ${TST_CMD} download "${TST_LOGIN}/test_env" -o env_tmp || (echo -e "\\n\\n/!\\\\ Download environment test failed.\\n" && exit 1)
# [ "$(find env_tmp -name test_env.yml | wc -l)" = 1 ] || (echo -e "\\n\\n/!\\\\ Download environment test failed.\\n" && exit 1)
# rm -rf env_tmp
# echo
#
# echo -e "/?\\\\ Remove environment:\\n"
# echo -e "spawn ${TST_CMD} remove \"${TST_LOGIN}/test_env\"\\nexpect {\\n  \"Are you sure you want to remove the package \" {\\n    send -- \"y\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Remove environment test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Copy package:\\n"
# ${TST_CMD} copy --from-label main --to-label test anaconda/pip/21.2.4 || (echo -e "\\n\\n/!\\\\ Copy package test failed.\\n" && exit 1)
# echo
#
# ${TST_CMD} copy --from-label main --to-label test anaconda/git-lfs/2.13.3 || (echo -e "\\n\\n/!\\\\ Copy package test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Move package:\\n"
# ${TST_CMD} move --from-label test --to-label demo "${TST_LOGIN}/pip/21.2.4" || (echo -e "\\n\\n/!\\\\ Move package test failed.\\n" && exit 1)
# echo
#
# ${TST_CMD} move --from-label test --to-label demo "${TST_LOGIN}/git-lfs/2.13.3" || (echo -e "\\n\\n/!\\\\ Move package test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Download copied package:\\n"
# rm -rf pkg_tmp
# mkdir -p pkg_tmp/linux-32 pkg_tmp/linux-64 pkg_tmp/linux-aarch64 pkg_tmp/linux-ppc64le pkg_tmp/linux-s390x pkg_tmp/noarch pkg_tmp/osx-64 pkg_tmp/osx-arm64 pkg_tmp/win-32 pkg_tmp/win-64
# ${TST_CMD} download "${TST_LOGIN}/pip" -o pkg_tmp || (echo -e "\\n\\n/!\\\\ Download copied package test failed.\\n" && exit 1)
# [ "$(find pkg_tmp -name 'pip-21.2.4-*.tar.bz2' | wc -l)" ">" 0 ] || (echo -e "\\n\\n/!\\\\ Download copied package test failed.\\n" && exit 1)
# rm -rf pkg_tmp
# echo
#
# rm -rf pkg_tmp
# mkdir -p pkg_tmp/linux-32 pkg_tmp/linux-64 pkg_tmp/linux-aarch64 pkg_tmp/linux-ppc64le pkg_tmp/linux-s390x pkg_tmp/noarch pkg_tmp/osx-64 pkg_tmp/osx-arm64 pkg_tmp/win-32 pkg_tmp/win-64
# ${TST_CMD} download "${TST_LOGIN}/git-lfs" -o pkg_tmp || (echo -e "\\n\\n/!\\\\ Download copied package test failed.\\n" && exit 1)
# [ "$(find pkg_tmp -name 'git-lfs-2.13.3-*.tar.bz2' | wc -l)" ">" 0 ] || (echo -e "\\n\\n/!\\\\ Download copied package test failed.\\n" && exit 1)
# rm -rf pkg_tmp
# echo
#
# echo -e "/?\\\\ Remove copied package:\\n"
# echo -e "spawn ${TST_CMD} remove ${TST_LOGIN}/pip\\nexpect {\\n  \"Are you sure you want to remove the package \" {\\n    send -- \"y\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Remove copied package test failed.\\n" && exit 1)
# echo
#
# echo -e "spawn ${TST_CMD} remove ${TST_LOGIN}/git-lfs\\nexpect {\\n  \"Are you sure you want to remove the package \" {\\n    send -- \"y\\\\r\"\\n  }\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n}\\nexpect {\\n  timeout {\\n    send_user \"\\\\n\\\\nUnexpected application state.\\\\n\"\\n    exit 67\\n  }\\n  eof {\\n    exit 0\\n  }\\n}\\n" | expect || (echo -e "\\n\\n/!\\\\ Remove copied package test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Logout:\\n"
# ${TST_CMD} logout || (echo -e "\\n\\n/!\\\\ Logout test failed.\\n" && exit 1)
# echo
#
# echo -e "/?\\\\ Success!\\n\\nAll tests have passed!\\n"

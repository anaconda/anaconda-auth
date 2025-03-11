# Manual test cases for anaconda-auth

The following tests require that the user has a valid subscription to an organization with a Business subscription.
A token should be created manually before the tests.
It will then be created again and re-provisioned interactively.

In general, we test the available and access to specific channels using the `conda search flask` command and examining the output.

## CASE: Default configuration will pull packages from repo.anaconda.com/pkgs/main

### GIVEN:

* A base Miniconda or Anaconda installation
* No tokens are installed (remove `~/.anaconda/keyring`, back it up first to restore it later)

### WHEN:

* Run: `conda search flask`

### THEN:

* The channel for all the packages should be `pkgs/main`

## CASE: Legacy install with conda-token

This checks that the token can be installed and used via the legacy method.

### GIVEN

* A base Miniconda or Anaconda installation
* No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)

### WHEN:

* run: `conda token set <TOKEN>`
* Follow prompts, accepting everything
* run: `conda search flask`

### THEN:

* The channel for all the packages should be `repo/main`

## CASE: New install with manually-provisioned token

### GIVEN:

* A base Miniconda or Anaconda installation
* No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)

### WHEN:

* run: `anaconda token install --org <ORG_NAME> <TOKEN>`
* Follow prompts, accepting everything
* run: `conda search flask`

### THEN:

* The channel for all the packages should be `repo/main`

## CASE: New interactive token grant flow for a user with a Business subscription

### GIVEN:

* A base Miniconda or Anaconda installation
* No tokens are installed (remove ~/.anaconda/keyring, back it up first to restore it later)
* User belongs to an organization with a Business subscription

### WHEN:

* Run: `anaconda token install`
* Follow prompts, accepting everything
* run: `conda search flask`

### THEN:

* The channel for all the packages should be "repo/main"

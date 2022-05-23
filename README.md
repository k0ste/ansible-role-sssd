# ansible-role-sssd

sssd - System Security Services Daemon. SSSD provides a set of daemons to manage
access to remote directories and authentication mechanisms. It provides an NSS
and PAM interface toward the system and a pluggable backend system to connect to
multiple different account sources as well as D-Bus interface. It is also the
basis to provide client auditing and policy services for projects like FreeIPA.
It provides a more robust database to store local users as well as extended user
data.

## Requirements

* Ansible 3.0.0+;

## Example configuration

```yaml
---
sssd:
# Enable sssd service or not.
- enable: 'true'
# Restart sssd services or not.
  restart: 'true'
# Install sssd package or not.
  install_package: 'true'
# 'present' (do nothing if package is already installed) or 'latest' (always
# upgrade to last version)
  package_state: 'latest'
  logger: 'journald'
# Location where SSSD will send log messages.
# stderr - redirect debug messages to standard error output;
# files - redirect debug messages to the log files. By default, the log files
# are stored in /var/log/sssd and there are separate log files for every SSSD
# service and domain;
# journald - redirect debug messages to systemd-journald.
  settings:
# Individual pieces of SSSD functionality are provided by special SSSD services
# that are started and stopped together with SSSD. The services are managed by
# a special service frequently called "monitor". The 'sssd' section is used to
# configure the monitor as well as some other important options like the
# identity domains.
  - sssd:
# Indicates what is the syntax of the config file. SSSD 0.6.0 and later use
# version 2.
    - config_file_version: '2'
# List of services that are started when sssd itself starts.  The services
# list is optional on platforms where systemd is supported, as they will either
# be socket or D-Bus activated when needed. Supported services: 'nss', 'pam' ,
# 'sudo' , 'autofs' , 'ssh' , 'pac' , 'ifp'.
      services:
      - 'nss'
      - 'pam'
      - 'sudo'
      - 'ssh'
# Number of times services should attempt to reconnect in the event of a Data
# Provider crash or restart before they give up. Default is '3'.
      reconnection_retries: '3'
# A domain is a database containing user information. SSSD can use more domains
# at the same time, but at least one must be configured or SSSD won't start.
# This parameter describes the list of domains in the order you want them to be
# queried. A domain name should only consist of alphanumeric ASCII characters,
# dashes, dots and underscores.
      domains:
      - name: 'LDAP'
# Specifies whether the domain is meant to be used by POSIX-aware clients such
# as the Name Service Switch or by applications that do not need POSIX data to
# be present or generated. Only objects from POSIX domains are available to the
# operating system interfaces and utilities. Allowed values for this option are
# "posix" (the default) and "application". POSIX domains are reachable by all
# services. Application domains are only reachable from the InfoPipe responder
# and the PAM responder. The application domains are currently well tested with
# "id_provider=ldap" only. For an easy way to configure a non-POSIX domains,
# please see the "Application domains" section.
        domain_type: ''
# UID and GID limits for the domain. If a domain contains an entry that is
# outside these limits, it is ignored. For users, this affects the primary GID
# limit. The user will not be returned to NSS if either the UID or the primary
# GID is outside the range. For non-primary group memberships, those that are
# in range will be reported as expected. These ID limits affect even saving
# entries to cache, not only returning them by name or ID. Default is '1' for
# 'min_id', '0' (no limit) for 'max_id'.
        min_id: '1'
        max_id: '0'
# Determines if a domain can be enumerated, that is, whether the domain can
# list all the users and group it contains. Note that it is not required to
# enable enumeration in order for secondary groups to be displayed. When 'true'
# users and groups are enumerated. When 'false' - no enumerations for this
# domain (the default). Enumerating a domain requires SSSD to download and
# store ALL user and group entries from the remote server. Enabling enumeration
# has a moderate performance impact on SSSD while enumeration is running. It
# may take up to several minutes after SSSD startup to fully complete
# enumerations. During this time, individual requests for information will go
# directly to LDAP, though it may be slow, due to the heavy enumeration
# processing. Saving a large number of entries to cache after the enumeration
# completes might also be CPU intensive as the memberships have to be
# recomputed. This can lead to the "sssd_be" process becoming unresponsive or
# even restarted by the internal watchdog. While the first enumeration is
# running, requests for the complete user or group lists may return no results
# until it completes. Further, enabling enumeration may increase the time
# necessary to detect network disconnection, as longer timeouts are required
# to ensure that enumeration lookups are completed successfully. For more
# information, refer to the man pages for the specific id_provider in use.
# For the reasons cited above, enabling enumeration is not recommended,
# especially in large environments.
        enumerate: 'false'
# Whether any of autodetected trusted domains should be enumerated. The
# supported values are:
# 'all' - all discovered trusted domains will be enumerated;
# 'none' - no discovered trusted domains will be enumerated (the default);
# Optionally, a list of one or more domain names can enable enumeration just
# for these trusted domains.
        subdomain_enumerate: 'none'
# How many seconds should nss_sss consider entries valid before asking the
# backend again. The cache expiration timestamps are stored as attributes of
# individual objects in the cache. Therefore, changing the cache timeout only
# has effect for newly added or expired entries. You should run the sss_cache
# tool in order to force refresh of entries that have already been cached.
# Default is '5400'.
        entry_cache_timeout: '5400'
# How many seconds should nss_sss consider user entries valid before asking the
# backend again. Default = 'entry_cache_timeout'.
        entry_cache_user_timeout: ''
# How many seconds should nss_sss consider group entries valid before asking the
# backend again. Default = 'entry_cache_timeout'.
        entry_cache_group_timeout: ''
# How many seconds should nss_sss consider netgroup entries valid before asking
# the backend again. Default = 'entry_cache_timeout'.
        entry_cache_netgroup_timeout: ''
# How many seconds should nss_sss consider service entries valid before asking
# the backend again. Default = 'entry_cache_timeout'.
        entry_cache_service_timeout: ''
# How many seconds should nss_sss consider hosts and networks entries valid
# before asking the backend again. Default = 'entry_cache_timeout'.
        entry_cache_resolver_timeout: ''
# How many seconds should sudo consider rules valid before asking the backend
# again. Default = 'entry_cache_timeout'.
        entry_cache_sudo_timeout: ''
# How many seconds should the autofs service consider automounter maps valid
# before asking the backend again. Default = 'entry_cache_timeout'.
        entry_cache_autofs_timeout: ''
# How many seconds to keep a host ssh key after refresh. IE how long to cache
# the host key for. Default = 'entry_cache_timeout'.
        entry_cache_ssh_host_timeout: ''
# How many seconds to keep the local computer entry before asking the backend
# again. Default = 'entry_cache_timeout'.
        entry_cache_computer_timeout: ''
# Specifies how many seconds SSSD has to wait before triggering a background
# refresh task which will refresh all expired or nearly expired records.
# The background refresh will process users, groups and netgroups in the cache.
# For users who have performed the initgroups (get group membership for user,
# typically ran at login) operation in the past, both the user entry and the
# group membership are updated. This option is automatically inherited for all
# trusted domains. You can consider setting this value to
# 3/4 * 'entry_cache_timeout'. Cache entry will be refreshed by background task
# when 2/3 of cache timeout has already passed. If there are existing cached
# entries, the background task will refer to their original cache timeout values
# instead of current configuration value. This may lead to a situation in which
# background refresh task appears to not be working. This is done by design to
# improve offline mode operation and reuse of existing valid cache entries. To
# make this change instant the user may want to manually invalidate existing
# cache. Default is '0' (disabled).
        refresh_expired_interval: '0'
# Determines if user credentials are also cached in the local LDB cache. User
# credentials are stored in a SHA512 hash, not in plaintext. Default is 'false'.
        cache_credentials: 'false'
# If 2-Factor-Authentication (2FA) is used and credentials should be saved this
# value determines the minimal length the first authentication factor (long
# term password) must have to be saved as SHA512 hash into the cache. This
# should avoid that the short PINs of a PIN based 2FA scheme are saved in the
# cache which would make them easy targets for brute-force attacks. Default is
# '8'.
        cache_credentials_minimal_first_factor_length: '8'
# Number of days entries are left in cache after last successful login before
# being removed during a cleanup of the cache. 0 means keep forever. The value
# of this parameter must be greater than or equal to
# 'offline_credentials_expiration'. Default is '0' (unlimited).
        account_cache_expiration: '0'
# Display a warning N days before the password expires. If zero is set, then
# this filter is not applied, i.e. if the expiration warning was received from
# backend server, it will automatically be displayed. Please note that the
# backend server has to provide information about the expiration time of the
# password. If this information is missing, sssd cannot display a warning. Also
# an auth provider has to be configured for the backend. Default is
# '7' (Kerberos), '0' (LDAP).
        pwd_expiration_warning: ''
# The identification provider used for the domain. Supported ID providers are:
# proxy - support a legacy NSS provider;
# files - FILES provider. See man sssd-files for more information on how to
# mirror local users and groups into SSSD;
# ldap - LDAP provider. See man sssd-ldap for more information on configuring
# LDAP;
# ipa - FreeIPA and Red Hat Enterprise Identity Management provider. See
# man sssd-ipa for more information on configuring FreeIPA;
# ad - Active Directory provider. See man sssd-ad for more information on
# configuring Active Directory;
        id_provider: ''
# Use the full name and domain (as formatted by the domain's full_name_format)
# as the user's login name reported to NSS. If set to 'true', all requests to
# this domain must use fully qualified names. For example, if used in LOCAL
# domain that contains a "test" user, getent passwd test wouldn't find the user
# while getent passwd test@LOCAL would. This option has no effect on netgroup
# lookups due to their tendency to include nested netgroups without qualified
# names. For netgroups, all domains will be searched when an unqualified
# name is requested. Default is 'false' ('true' for trusted domain/sub-domains
# or if default_domain_suffix is used)
        use_fully_qualified_names: 'false'
# Do not return group members for group lookups. If set to 'true', the group
# membership attribute is not requested from the ldap server, and group members
# are not returned when processing group lookup calls, such as getgrnam or
# getgrgid. As an effect, "getent group $groupname" would return the requested
# group as if it was empty. Enabling this option can also make access provider
# checks for group membership significantly faster, especially for groups
# containing many members. Default is 'false'.
        ignore_group_members: 'false'
# The authentication provider used for the domain. Supported auth providers are:
# ldap - for native LDAP authentication. See man sssd-ldap for more
# information on configuring LDAP;
# krb5 - for Kerberos authentication. See man sssd-krb5 for more information on
# configuring Kerberos;
# ipa - FreeIPA and Red Hat Enterprise Identity Management provider. See man
# sssd-ipa for more information on configuring FreeIPA;
# ad - Active Directory provider. See man sssd-ad for more information on
# configuring Active Directory;
# proxy - for relaying authentication to some other PAM target;
# none - disables authentication explicitly;
# Default 'id_provider' is used if it is set and can handle authentication
# requests.
        auth_provider: ''
# The access control provider used for the domain. There are two built-in access
# providers (in addition to any included in installed backends) Internal special
# providers are:
# permit - always allow access. It's the only permitted access provider for a
# local domain (the default);
# deny - always deny access;
# ldap - for native LDAP authentication. See man sssd-ldap for more information
# on configuring LDAP;
# ipa - FreeIPA and Red Hat Enterprise Identity Management provider. See man
# sssd-ipa for more information on configuring FreeIPA;
# ad - Active Directory provider. See man sssd-ad for more information on
# configuring Active Directory;
# simple - access control based on access or deny lists. See man sssd-simple for
# more information on configuring the simple access module;
# krb5: .k5login based access control. See sssd-krb5(5) for more information
# on configuring Kerberos;
# proxy - for relaying access control to another PAM module.
        access_provider: 'proxy'
# The provider which should handle change password operations for the domain.
# Supported change password providers are:
# ldap - to change a password stored in a LDAP server. See man sssd-ldap for
# more information on configuring LDAP;
# krb5 - to change the Kerberos password. See man sssd-krb5 for more information
# on configuring Kerberos;
# ipa - FreeIPA and Red Hat Enterprise Identity Management provider. See
# sssd-ipa for more information on configuring FreeIPA;
# ad - Active Directory provider. See man sssd-ad for more information on
# configuring Active Directory;
# proxy - for relaying password changes to some other PAM target;
# none - disallows password changes explicitly;
# Default is auth_provider is used if it is set and can handle change password
# requests.
        chpass_provider: ''
# The SUDO provider used for the domain. Supported SUDO providers are:
# ldap - for rules stored in LDAP. See man sssd-ldap for more information on
# configuring LDAP;
# ipa - the same as "ldap" but with IPA default settings;
# ad - the same as "ldap" but with AD default settings;
# none - disables SUDO explicitly;
# Default: The value of "id_provider" is used if it is set.
# Sudo rules are periodically downloaded in the background unless the sudo
# provider is explicitly disabled. Set 'sudo_provider' to 'none' to disable all
# sudo-related activity in SSSD if you do not want to use sudo with SSSD at all.
        sudo_provider: ''
# The provider which should handle loading of selinux settings. Note that this
# provider will be called right after access provider ends. Supported selinux
# providers are:
# ipa - to load selinux settings from an IPA server. See man sssd-ipa for more
# information on configuring IPA;
# none - disallows fetching selinux settings explicitly;
# Default: 'id_provider' is used if it is set and can handle selinux loading
# requests.
        selinux_provider: ''
# The provider which should handle fetching of subdomains. This value should be
# always the same as id_provider. Supported subdomain providers are:
# ipa - to load a list of subdomains from an IPA server. See man sssd-ipa for
# more information on configuring IPA;
# ad - to load a list of subdomains from an Active Directory server. See
# man sssd-ad for more information on configuring the AD provider;
# none - disallows fetching subdomains explicitly;
# Default: the value of 'id_provider' is used if it is set.
        subdomains_provider: ''
# The provider which configures and manages user session related tasks. The only
# user session task currently provided is the integration with Fleet Commander,
# which works only with IPA. Supported session providers are:
# ipa - to allow performing user session related tasks;
# none - does not perform any kind of user session related tasks;
# Default is id_provider is used if it is set and can perform session related
# tasks. In order to have this feature working as expected SSSD must be running
# as "root" and not as the unprivileged user.
        session_provider: ''
# The autofs provider used for the domain. Supported autofs providers are:
# ldap - to load maps stored in LDAP. See man sssd-ldap for more information on
# configuring LDAP;
# ipa - to load maps stored in an IPA server. See man sssd-ipa for more
# information on configuring IPA;
# ad - to load maps stored in an AD server. See man sssd-ad for more
# information on configuring the AD provider;
# none - disables autofs explicitly;
# Default the value of 'id_provider' is used if it is set.
        autofs_provider: ''
# The provider used for retrieving host identity information. Supported hostid
# providers are:
# ipa - to load host identity stored in an IPA server. See man sssd-ipa for
# more information on configuring IPA;
# none - disables hostid explicitly;
# Default the value of 'id_provider' is used if it is set.
        hostid_provider: ''
# The provider which should handle hosts and networks lookups. Supported
# resolver providers are:
# proxy - to forward lookups to another NSS library. See
# 'proxy_resolver_lib_name';
# ldap - to fetch hosts and networks stored in LDAP. See man sssd-ldap for more
# information on configuring LDAP;
# ad - to fetch hosts and networks stored in AD. See man sssd-ad for more
# information on configuring the AD provider;
# none - disallows fetching hosts and networks explicitly;
# Default the value of 'id_provider' is used if it is set.
        resolver_provider: ''
# Regular expression for this domain that describes how to parse the string
# containing user name and domain into these components. The "domain" can match
# either the SSSD configuration domain name, or, in the case of IPA trust
# subdomains and Active Directory domains, the flat (NetBIOS) name of the
# domain. Default for the AD and IPA provider:
# "(((?P<domain>[^\\]+)\\(?P<name>.+$))|((?P<name>[^@]+)@(?P<domain>.+$))|(^(?P<name>[^@\\]+)$))"
# which allows three different styles for user names:
# * username
# * username@domain.name
# * domain\username
# While the first two correspond to the general default the third one is
# introduced to allow easy integration of users from Windows domains.
# Default: "(?P<name>[^@]+)@?(?P<domain>[^@]*$)" which translates to
# "the name is everything up to the '@' sign, the domain everything after that".
# Some Active Directory groups, typically those used for MS Exchange contain an
# '@' sign in the name, which clashes with the default re_expression value for
# the AD and IPA providers. To support these groups, consider changing the
# 're_expression' value to: "((?P<name>.+)@(?P<domain>[^@]+$))".
        re_expression: ''
# A printf-compatible format that describes how to compose a fully qualified
# name from user name and domain name components.
# The following expansions are supported:
# '%1$s' - user name;
# '%2$s' - domain name as specified in the SSSD config file;
# '%3$s' - domain flat name. Mostly usable for Active Directory domains, both
# directly configured or discovered via IPA trusts. Default is '%1$s@%2$s'.
        full_name_format: '%1$s@%2$s'
# Provides the ability to select preferred address family to use when performing
# DNS lookups. Supported values:
# ipv4_first - try looking up IPv4 address, if that fails, try
# IPv6 (the default);
# ipv4_only - only attempt to resolve hostnames to IPv4 addresses;
# ipv6_first - try looking up IPv6 address, if that fails, try IPv4;
# ipv6_only - only attempt to resolve hostnames to IPv6 addresses.
        lookup_family_order: 'ipv4_first'
# Defines the amount of time (in seconds) to wait for a reply from the internal
# fail over service before assuming that the service is unreachable. If this
# timeout is reached, the domain will continue to operate in offline mode.
# Default is '6'.
        dns_resolver_timeout: '6'
# If service discovery is used in the back end, specifies the domain part of the
# service discovery DNS query. Default is use the domain part of machine's
# hostname.
        dns_discovery_domain: ''
# Override the primary GID value with the one specified.
        override_gid: ''
# Treat user and group names as case sensitive. Possible option values are:
# true - case sensitive. This value is invalid for AD provider;
# false - case insensitive;
# preserving - same as 'false' (case insensitive), but does not lowercase names
# in the result of NSS operations. Note that name aliases (and in case of
# services also protocol names) are still lowercased in the output. Default is
# 'true' ('false' for AD provider).
        case_sensitive: ''
# Specifies a list of configuration parameters that should be inherited by a
# subdomain. Please note that only selected parameters can be inherited.
# Currently the following options can be inherited:
# 'ignore_group_members', 'ldap_purge_cache_timeout', 'ldap_use_tokengroups',
# 'ldap_user_principal', 'ldap_krb5_keytab' (the value of 'krb5_keytab' will be
# used if 'ldap_krb5_keytab' is not set explicitly). Default is None. This
# option only works with the IPA and AD provider.
        subdomain_inherit: ''
# Use this homedir as default value for all subdomains within this domain in
# IPA AD trust. See 'override_homedir' for info about possible values. In
# addition to those, the expansion below can only be used with
# 'subdomain_homedir'. '%F' - flat (NetBIOS) name of a subdomain. The value can
# be overridden by override_homedir option. Default is '/home/%d/%u'.
        subdomain_homedir: ''
# Various tags stored by the realmd configuration service for this domain.
        realmd_tags: ''
# Specifies time in seconds since last successful online authentication for
# which user will be authenticated using cached credentials while SSSD is in
# the online mode. If the credentials are incorrect, SSSD falls back to online
# authentication. This option's value is inherited by all trusted domains. At
# the moment it is not possible to set a different value per trusted domain.
# Special value 0 implies that this feature is disabled. Please note that if
# 'cached_auth_timeout' is longer than 'pam_id_timeout' then the back end could
# be called to handle "initgroups". Default is '0'.
        cached_auth_timeout: '0'
# This option takes any of three available values:
# true - create user's private group unconditionally from user's UID number.
# The GID number is ignored in this case. Because the GID number and the user
# private group are inferred from the UID number, it is not supported to have
# multiple entries with the same UID or GID number with this option. In other
# words, enabling this option enforces uniqueness across the ID space;
# false - always use the user's primary GID number. The GID number must refer
# to a group object in the LDAP database;
# hybrid - a primary group is autogenerated for user entries whose UID and GID
# numbers have the same value and at the same time the GID number does not
# correspond to a real group object in LDAP. If the values are the same, but
# the primary GID in the user entry is also used by a group object, the primary
# GID of the user resolves to that group object;
# If the UID and GID of a user are different, then the GID must correspond to a
# group entry, otherwise the GID is simply not resolvable. This feature is
# useful for environments that wish to stop maintaining a separate group objects
# for the user private groups, but also wish to retain the existing user private
# groups;
        auto_private_groups: ''
# The proxy target PAM proxies to. Default is None, you have to take an existing
# pam configuration or create a new one and add the service name here.
        proxy_pam_target: ''
# The name of the NSS library to use in proxy domains. The NSS functions
# searched for in the library are in the form of _nss_$(libName)_$(function),
# for example _nss_files_getpwent.
        proxy_lib_name: ''
# The name of the NSS library to use for hosts and networks lookups in proxy
# domains. The NSS functions searched for in the library are in the form of
# _nss_$(libName)_$(function), for example _nss_dns_gethostbyname2_r.
        proxy_resolver_lib_name: ''
# When a user or group is looked up by name in the proxy provider, a second
# lookup by ID is performed to "canonicalize" the name in case the requested
# name was an alias. Setting this option to 'true' would cause the SSSD to
# perform the ID lookup from cache for performance reasons. Default is 'false'.
        proxy_fast_alias: 'false'
# This option specifies the number of pre-forked proxy children. It is useful
# for high-load SSSD environments where sssd may run out of available child
# slots, which would cause some issues due to the requests being queued.
# Default is '10'.
        proxy_max_children: '10'
# Specifies the list of URIs of the LDAP servers to which SSSD should connect in
# the order of preference. If neither option is specified, service discovery is
# enabled.
        ldap_uri: 'ldaps://127.0.0.1:389'
        ldap_backup_uri: 'ldaps://100.100.100.1:389'
# Specifies the list of URIs of the LDAP servers to which SSSD should connect in
# the order of preference to change the password of a user. To enable service
# discovery 'ldap_chpass_dns_service_name' must be set. Default is None, i.e.
# 'ldap_uri' is used.
        ldap_chpass_uri: ''
        ldap_chpass_backup_uri: ''
# The default base DN to use for performing LDAP user operations. Examples:
# - 'dc=example,dc=com' which is equivalent to 'dc=example,dc=com?subtree?';
# - 'cn=host_specific,dc=example,dc=com?subtree?(host=thishost)?dc=example.com?subtree?'
# It is unsupported to have multiple search bases which reference
# identically-named objects (for example, groups with the same name in two
# different search bases). This will lead to unpredictable behavior on client
# machines. Default: if not set, the value of the defaultNamingContext or
# namingContexts attribute from the RootDSE of the LDAP server is used. If
# defaultNamingContext does not exist or has an empty value namingContexts is
# used. The namingContexts attribute must have a single value with the DN of the
# search base of the LDAP server to make this work. Multiple values are are not
# supported.
        ldap_search_base: 'dc=example,dc=com'
# Specifies the Schema Type in use on the target LDAP server. Depending on the
# selected schema, the default attribute names retrieved from the servers may
# vary. The way that some attributes are handled may also differ. Four schema
# types are currently supported: 'rfc2307' (the default), 'rfc2307bis', 'IPA',
# 'AD'. The main difference between these schema types is how group memberships
# are recorded in the server. With 'rfc2307', group members are listed by name
# in the "memberUid" attribute. With 'rfc2307bis' and 'IPA', group members are
# listed by DN and stored in the "member" attribute. The AD schema type sets the
# attributes to correspond with Active Directory 2008r2 values.
        ldap_schema: 'rfc2307'
# Specify the operation that is used to modify user password.
# Two modes are currently supported:
# exop - Password Modify Extended Operation (RFC 3062) (the default);
# ldap_modify - direct modification of userPassword (not recommended).
# First, a new connection is established to verify current password by binding
# as the user that requested password change. If successful, this connection is
# used to change the password therefore the user must have write access to
# "userPassword" attribute.
        ldap_pwmodify_mode: 'exop'
# The default bind DN to use for performing LDAP operations.
        ldap_default_bind_dn: 'uid=reader,ou=users,ou=accounts,dc=example,dc=com'
# The type of the authentication token of the default bind DN. The two
# mechanisms currently supported are: 'password' (the default),
# 'obfuscated_password'.
        ldap_default_authtok_type: 'password'
# The authentication token of the default bind DN.
        ldap_default_authtok: 'secret'
# Some directory servers, for example Active Directory, might deliver the realm
# part of the UPN in lower case, which might cause the authentication to fail.
# Set this option to a non-zero value if you want to use an upper-case realm.
# Default is 'false'.
        ldap_force_upper_case_realm: 'false'
# Specifies how many seconds SSSD has to wait before refreshing its cache of
# enumerated records. Default is '300'.
        ldap_enumeration_refresh_timeout: '300'
# Determine how often to check the cache for inactive entries (such as groups
# with no members and users who have never logged in) and remove them to save
# space. Setting this option to zero will disable the cache cleanup operation.
# Please note that if enumeration is enabled, the cleanup task is required in
# order to detect entries removed from the server and can't be disabled. By
# default, the cleanup task will run every 3 hours with enumeration enabled.
# Default is '0' (disabled).
        ldap_purge_cache_timeout: '0'
# If ldap_schema is set to a schema format that supports nested groups (e.g.
# RFC2307bis), then this option controls how many levels of nesting SSSD will
# follow. This option has no effect on the RFC2307 schema. This option specifies
# the guaranteed level of nested groups to be processed for any lookup. However,
# nested groups beyond this limit may be returned if previous lookups already
# resolved the deeper nesting levels. Also, subsequent lookups for other groups
# may enlarge the result set for original lookup if re-queried. If
# 'ldap_group_nesting_level' is set to '0' then no nested groups are processed
# at all. However, when connected to Active-Directory Server 2008 and later
# using 'id_provider' in 'ad' it is furthermore required to disable usage of
# Token-Groups by setting 'ldap_use_tokengroups' to 'false' in order to restrict
# group nesting. Default is '2'.
        ldap_group_nesting_level: '2'
# This options enables or disables use of Token-Groups attribute when
# performing initgroup for users from Active Directory Server 2008 and later.
# Default is 'true' for AD and IPA otherwise 'false'.
        ldap_use_tokengroups: ''
# Use the given string as search base for host objects. See 'ldap_search_base'
# for information about configuring multiple search bases. Default is the value
# of 'ldap_search_base'.
        ldap_host_search_base: ''
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of 'base', 'onelevel' or
# 'subtree'. The filter must be a valid LDAP search filter as specified by
# RFC2254. For examples of this syntax, please refer to the 'ldap_search_base'
# examples section. Default is the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an Active
# Directory Server that might yield a large number of results and trigger the
# Range Retrieval extension in the response.
        ldap_service_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of 'base', 'onelevel' or
# 'subtree'. The filter must be a valid LDAP search filter as specified by
# RFC2254. For examples of this syntax, please refer to the 'ldap_search_base'
# examples section. Default is the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an Active
# Directory Server that might yield a large number of results and trigger the
# Range Retrieval extension in the response.
        ldap_iphost_search_base: ''
        ldap_ipnetwork_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# Specifies the timeout (in seconds) that ldap searches are allowed to run
# before they are cancelled and cached results are returned (and offline mode is
# entered). This option is subject to change in future versions of the SSSD. It
# will likely be replaced at some point by a series of timeouts for specific
# lookup types. Default is '6'.
        ldap_search_timeout: '6'
# Specifies the timeout (in seconds) that ldap searches for user and group
# enumerations are allowed to run before they are cancelled and cached results
# are returned (and offline mode is entered). Default is '60'.
        ldap_enumeration_search_timeout: '60'
# Specifies the timeout (in seconds) after which the poll/select following a
# connect returns in case of no activity. Default is '6'.
         ldap_network_timeout: '6'
# Specifies a timeout (in seconds) after which calls to synchronous LDAP APIs
# will abort if no response is received. Also controls the timeout when
# communicating with the KDC in case of SASL bind, the timeout of an LDAP bind
# operation, password change extended operation and the StartTLS operation.
# Default is '8'.
         ldap_opt_timeout: '8'
# Specifies a timeout (in seconds) that a connection to an LDAP server will be
# maintained. After this time, the connection will be re-established. If used in
# parallel with SASL/GSSAPI, the sooner of the two values (this value vs. the
# TGT lifetime) will be used. This timeout can be extended of a random value
# specified by 'ldap_connection_expire_offset'. Default is '900' (15 minutes).
        ldap_connection_expire_timeout: '900'
# Random offset between 0 and configured value is added to
# 'ldap_connection_expire_timeout'. Default is '0'.
        ldap_connection_expire_offset: '0'
# Specify the number of records to retrieve from LDAP in a single request. Some
# LDAP servers enforce a maximum limit per-request. Default is '1000'.
        ldap_page_size: '1000'
# Disable the LDAP paging control. This option should be used if the LDAP server
# reports that it supports the LDAP paging control in its RootDSE but it is not
# enabled or does not behave properly. Default is 'false'.
        ldap_disable_paging: 'false'
# Disable Active Directory range retrieval. Active Directory limits the number
# of members to be retrieved in a single lookup using the MaxValRange policy
# (which defaults to 1500 members). If a group contains more members, the reply
# would include an AD-specific range extension. This option disables parsing of
# the range extension, therefore large groups will appear as having no members.
# Default is false.
        ldap_disable_range_retrieval: 'false'
# When communicating with an LDAP server using SASL, specify the minimum
# security level necessary to establish the connection. The values of this
# option are defined by OpenLDAP. Default is use the system default (usually
# specified by ldap.conf).
        ldap_sasl_minssf: ''
# When communicating with an LDAP server using SASL, specify the maximal
# security level necessary to establish the connection. The values of this
# option are defined by OpenLDAP. Default is use the system default (usually
# specified by ldap.conf).
        ldap_sasl_maxssf: ''
# Specify the number of group members that must be missing from the internal
# cache in order to trigger a dereference lookup. If less members are missing,
# they are looked up individually. You can turn off dereference lookups
# completely by setting the value to '0'. Please note that there are some
# codepaths in SSSD, like the IPA HBAC provider, that are only implemented
# using the dereference call, so even with dereference explicitly disabled,
# those parts will still use dereference if the server supports it and
# advertises the dereference control in the rootDSE object. A dereference lookup
# is a means of fetching all group members in a single LDAP call. Different
# LDAP servers may implement different dereference methods. The currently
# supported servers are 389/RHDS, OpenLDAP and Active Directory. If any of the
# search bases specifies a search filter, then the dereference lookup
# performance enhancement will be disabled regardless of this setting.
# Default is '10'.
        ldap_deref_threshold: '10'
# Specifies what checks to perform on server certificates in a TLS session, if
# any. It can be specified as one of the following values:
# never - the client will not request or check any server certificate;
# allow - the server certificate is requested. If no certificate is provided,
# the session proceeds normally. If a bad certificate is provided, it will be
# ignored and the session proceeds normally;
# try - the server certificate is requested. If no certificate is provided, the
# session proceeds normally. If a bad certificate is provided, the session is
# immediately terminated;
# demand - the server certificate is requested. If no certificate is provided,
# or a bad certificate is provided, the session is immediately terminated;
# hard - same as 'demand', this is default.
        ldap_tls_reqcert: 'hard'
# Specifies the file that contains certificates for all of the Certificate
# Authorities that sssd will recognize. Default: use OpenLDAP defaults,
# typically in /etc/openldap/ldap.conf
        ldap_tls_cacert: ''
# Specifies the path of a directory that contains Certificate Authority
# certificates in separate individual files. Typically the file names need to be
# the hash of the certificate followed by '.0'. If available, 'cacertdir_rehash'
# can be used to create the correct names. Default: use OpenLDAP defaults,
# typically in /etc/openldap/ldap.conf
        ldap_tls_cacertdir: ''
# Specifies the file that contains the certificate for the client's key.
        ldap_tls_cert: ''   
# Specifies the file that contains the client's key. Default is None.
        ldap_tls_key: ''
# Specifies acceptable cipher suites. Typically this is a colon separated list.
# Default: use OpenLDAP defaults, typically in '/etc/openldap/ldap.conf'.
        ldap_tls_cipher_suite: ''
# Specifies that the id_provider connection must also use tls to protect the
# channel. Default is 'false'.
        ldap_id_use_start_tls: 'false'
# Specifies that SSSD should attempt to map user and group IDs from the
# 'ldap_user_objectsid' and 'ldap_group_objectsid' attributes instead of
# relying on 'ldap_user_uid_number' and 'ldap_group_gid_number'. Currently this
# feature supports only ActiveDirectory objectSID mapping. Default is 'false'.
        ldap_id_mapping: 'false'
# In contrast to the SID based ID mapping which is used if 'ldap_id_mapping' is
# set to true the allowed ID range for 'ldap_user_uid_number' and
# 'ldap_group_gid_number' is unbound. In a setup with sub/trusted-domains this
# might lead to ID collisions. To avoid collisions 'ldap_min_id' and
# 'ldap_max_id' can be set to restrict the allowed range for the IDs which are
# read directly from the server. Sub-domains can then pick other ranges to map
# IDs. Default is None (both options are set to '0').
        ldap_min_id: ''
        ldap_max_id: ''
# Specify the SASL mechanism to use. Currently only GSSAPI and GSS-SPNEGO are
# tested and supported. If the backend supports sub-domains the value of
# 'ldap_sasl_mech' is automatically inherited to the sub-domains. If a
# different value is needed for a sub-domain it can be overwritten by setting
# 'ldap_sasl_mech' for this sub-domain explicitly. Default is None.
        ldap_sasl_mech: ''
# Specify the SASL authorization id to use. When GSSAPI/GSS-SPNEGO are used,
# this represents the Kerberos principal used for authentication to the
# directory. This option can either contain the full principal (for example
# host/myhost@EXAMPLE.COM) or just the principal name (for example host/myhost).
# By default, the value is not set and the following principals are used:
# hostname@REALM
# netbiosname$@REALM
# host/hostname@REALM
# *$@REALM
# host/*@REALM
# host/*
# If none of them are found, the first principal in keytab is returned.
# Default is 'host/hostname@REALM'.
        ldap_sasl_authid: 'host/hostname@REALM'
# Specify the SASL realm to use. When not specified, this option defaults to
# the value of 'krb5_realm'. If the ldap_sasl_authid contains the realm as well,
# this option is ignored. Default is the value of 'krb5_realm'.
        ldap_sasl_realm: ''
# If set to 'true', the LDAP library would perform a reverse lookup to
# canonicalize the host name during a SASL bind. Default is 'false'.
        ldap_sasl_canonicalize: 'false'
# Specify the keytab to use when using SASL/GSSAPI/GSS-SPNEGO. Default is use
# System keytab, normally '/etc/krb5.keytab'.
        ldap_krb5_keytab: '/etc/krb5.keytab'
# Specifies that the 'id_provider' should init Kerberos credentials (TGT). This
# action is performed only if SASL is used and the mechanism selected is GSSAPI
# or GSS-SPNEGO. Default is 'true'.
        ldap_krb5_init_creds: 'true'
# Specifies the lifetime in seconds of the TGT if GSSAPI or GSS-SPNEGO is used.
# Default is '86400' (24 hours).
        ldap_krb5_ticket_lifetime: '86400'
# Specifies the list of IP addresses or hostnames of the Kerberos servers to
# which SSSD should connect in the order of preference. An optional port number
# (preceded by a colon) may be appended to the addresses or hostnames. If empty,
# service discovery is enabled. When using service discovery for KDC or kpasswd
# servers, SSSD first searches for DNS entries that specify _udp as the protocol
# and falls back to _tcp if none are found. This option was named 'krb5_kdcip'
# in earlier releases of SSSD. While the legacy name is recognized for the time
# being, users are advised to migrate their config files to use 'krb5_server'
# instead.
        krb5_server: ''
        krb5_backup_server: ''
# Specify the Kerberos REALM (for SASL/GSSAPI/GSS-SPNEGO auth). Default is
# System defaults, see '/etc/krb5.conf'
        krb5_realm: ''
# If the change password service is not running on the KDC, alternative servers
# can be defined here. An optional port number (preceded by a colon) may be
# appended to the addresses or hostnames. NOTE: Even if there are no more
# kpasswd servers to try, the backend is not switched to operate offline if
# authentication against the KDC is still possible. Default: Use the KDC
        krb5_kpasswd: ''
        krb5_backup_kpasswd: ''
# Directory to store credential caches. All the substitution sequences of
# 'krb5_ccname_template' can be used here, too, except '%d' and '%P'. The
# directory is created as private and owned by the user, with permissions set
# to '0700'. Default is '/tmp'.
        krb5_ccachedir: '/tmp'
# Location of the user's credential cache. Three credential cache types are
# currently supported: "FILE", "DIR" and "KEYRING:persistent". The cache can be
# specified either as TYPE:RESIDUAL, or as an absolute path, which implies the
# "FILE" type. In the template, the following sequences are substituted:
# '%u' - login name
# '%U' - login UID
# '%p' - principal name
# '%r' - realm name
# '%h' - home directory
# '%d' - value of krb5_ccachedir
# '%P' - the process ID of the SSSD client
# '%%' - a literal '%'
# If the template ends with 'XXXXXX' mkstemp is used to create a unique filename
# in a safe way. When using KEYRING types, the only supported mechanism is
# "KEYRING:persistent:%U", which uses the Linux kernel keyring to store
# credentials on a per-UID basis. This is also the recommended choice, as it is
# the most secure and predictable method. NOTE: Please be aware that libkrb5
# ccache expansion template from krb5.conf uses different expansion sequences
# than SSSD.
        krb5_ccname_template: ''
# Timeout in seconds after an online authentication request or change password
# request is aborted. If possible, the authentication request is continued
# offline. Default is '6'.
        krb5_auth_timeout: '6'
# Verify with the help of krb5_keytab that the TGT obtained has not been
# spoofed. The keytab is checked for entries sequentially, and the first entry
# with a matching realm is used for validation. If no entry matches the realm,
# the last entry in the keytab is used. This process can be used to validate
# environments using cross-realm trust by placing the appropriate keytab entry
# as the last entry or the only entry in the keytab file. Default is 'false'.
        krb5_validate: 'false'
# Store the password of the user if the provider is offline and use it to
# request a TGT when the provider comes online again. NOTE: this feature is only
# available on Linux. Passwords stored in this way are kept in plaintext in the
# kernel keyring and are potentially accessible by the root user (with
# difficulty). Default is 'false'.
        krb5_store_password_if_offline: 'false'
# Request a renewable ticket with a total lifetime, given as an integer
# immediately followed by a time unit:
# 's' - for seconds
# 'm' - for minutes
# 'h' - for hours
# 'd' - for days
# If there is no unit given, 's' is assumed. NOTE: It is not possible to mix
# units. To set the renewable lifetime to one and a half hours, use '90m'
# instead of '1h30m'. Default: not set, i.e. the TGT is not renewable
        krb5_renewable_lifetime: ''
# Request ticket with a lifetime, given as an integer immediately followed by a
# time unit:
# 's' for seconds
# 'm' for minutes
# 'h' for hours
# 'd' for days.
# If there is no unit given 's' is assumed. NOTE: It is not possible to mix
# units. To set the lifetime to one and a half hours please use '90m' instead
# of '1h30m'. Default: not set, i.e. the default ticket lifetime configured on
# the KDC.
        krb5_lifetime: ''
# The time in seconds between two checks if the TGT should be renewed. TGTs are
# renewed if about half of their lifetime is exceeded, given as an integer
# immediately followed by a time unit:
# 's' for seconds
# 'm' for minutes
# 'h' for hours
# 'd' for days.
# If there is no unit given, s is assumed. NOTE: It is not possible to mix
# units. To set the renewable lifetime to one and a half hours, use '90m'
# instead of '1h30m'. If this option is not set or is 0 the automatic renewal
# is disabled. Default: not set.
        krb5_renew_interval: ''
# Enables flexible authentication secure tunneling (FAST) for Kerberos
# pre-authentication. The following options are supported:
# 'never' - use FAST. This is equivalent to not setting this option at all.
# 'try' - to use FAST. If the server does not support FAST, continue the
# authentication without it.
# 'demand' to use FAST. The authentication fails if the server does not require
# fast.
# Default: not set, i.e. FAST is not used. NOTE: a keytab is required to use
# FAST. NOTE: SSSD supports FAST only with MIT Kerberos version 1.8 and later.
# If SSSD is used with an older version of MIT Kerberos, using this option is a
# configuration error.
        krb5_use_fast: ''
# Specifies the server principal to use for FAST.
        krb5_fast_principal: ''
# When krb5_use_kdcinfo is set to true, you can limit the amount of servers
# handed to sssd_krb5_locator_plugin. This might be helpful when there are too
# many servers discovered using SRV record. The krb5_kdcinfo_lookahead option
# contains two numbers separated by a colon. The first number represents number
# of primary servers used and the second number specifies the number of backup
# servers. For example '10:0' means that up to 10 primary servers will be
# handed to sssd_krb5_locator_plugin but no backup servers. Default is '3:1'.
        krb5_kdcinfo_lookahead: '3:1'
# Specifies if the user principal should be treated as enterprise principal.
# See section 5 of RFC 6806 for more details about enterprise principals.
# Default: false (AD provider: true). The IPA provider will set to option to
# 'true' if it detects that the server is capable of handling enterprise
# principals and the option is not set explicitly in the config file.
        krb5_use_enterprise_principal: 'false'
# The list of mappings is given as a comma-separated list of pairs
# "username:primary" where "username" is a UNIX user name and "primary" is a
# user part of a kerberos principal. This mapping is used when user is
# authenticating using "auth_provider = krb5". Example: "joe" and "dick" are
# UNIX user names and "juser" and "richard" are primaries of kerberos
# principals. For user "joe" resp. "dick" SSSD will try to kinit as
# "juser@REALM" resp. "richard@REALM". Default is not set.
        krb5_map_user:
        - 'joe:juser'
        - 'dick:richard'
# Specifies if the host principal should be canonicalized when connecting to
# LDAP server. This feature is available with MIT Kerberos >= 1.7. Default is
# 'false'.
        krb5_canonicalize: 'false'
# Specifies if the SSSD should instruct the Kerberos libraries what realm and
# which KDCs to use. This option is on by default, if you disable it, you need
# to configure the Kerberos library using the krb5.conf configuration file.
# Default is 'true'.
        krb5_use_kdcinfo: 'true'
# Select the policy to evaluate the password expiration on the client side. The
# following values are allowed:
# none - no evaluation on the client side. This option cannot disable
# server-side password policies;
# shadow - use shadow style attributes to evaluate if the password has expired;
# mit_kerberos - use the attributes used by MIT Kerberos to determine if the
# password has expired. Use 'chpass_provider' in 'krb5' to update these
# attributes when the password is changed. Default is None. If a password policy
# is configured on server side, it always takes precedence over policy set with
# this option.
        ldap_pwd_policy: ''
# Specifies the service name to use when service discovery is enabled. Default
# is 'ldap'.
        ldap_dns_service_name: 'ldap'
# Specifies the service name to use to find an LDAP server which allows password
# changes when service discovery is enabled. Default is not set, i.e. service
# discovery is disabled.
        ldap_chpass_dns_service_name: ''
# Specifies whether to update the 'ldap_user_shadow_last_change' attribute with
# days since the Epoch after a password change operation. Default is 'false'.
        ldap_chpass_update_last_change: 'false'
# If using 'access_provider' in 'ldap' and 'ldap_access_order' in 'filter'
# (default), this option is mandatory. It specifies an LDAP search filter
# criteria that must be met for the user to be granted access on this host. If
# 'access_provider' in 'ldap', 'ldap_access_order' in 'filter' and this option
# is not set, it will result in all users being denied access. Use
# 'access_provider' in 'permit' to change this default behavior. Please note
# that this filter is applied on the LDAP user entry only and thus filtering
# based on nested groups may not work (e.g. "memberOf" attribute on AD entries
# points only to direct parents).
# Example:
# - access_provider: 'ldap'
#   ldap_access_filter: '(employeeType=admin)'
# This example means that access to this host is restricted to users whose
# employeeType attribute is set to "admin". Offline caching for this feature is
# limited to determining whether the user's last online login was granted access
# permission. If they were granted access during their last login, they will
# continue to be granted access while offline and vice versa. Default is empty.
        ldap_access_filter: ''
# With this option a client side evaluation of access control attributes can be
# enabled. Please note that it is always recommended to use server side access
# control, i.e. the LDAP server should deny the bind request with a suitable
# error code even if the password is correct. The following values are allowed:
# shadow - use the value of ldap_user_shadow_expire to determine if the account
# is expired;
# ad - use the value of the 32bit field 'ldap_user_ad_user_account_control' and
# allow access if the second bit is not set. If the attribute is missing access
# is granted. Also the expiration time of the account is checked;
# rhds, ipa, 389ds - use the value of 'ldap_ns_account_lock' to check if access
# is allowed or not;
# nds - the values of 'ldap_user_nds_login_allowed_time_map',
# 'ldap_user_nds_login_disabled' and 'ldap_user_nds_login_expiration_time' are
# used to check if access is allowed. If both attributes are missing access is
# granted. Please note that the 'ldap_access_order' configuration option must
# include "expire" in order for the 'ldap_account_expire_policy' option to work.
# Default is None.
        ldap_account_expire_policy: ''
# List of access control options. Allowed values are:
# filter - use 'ldap_access_filter' (the default);
# lockout - use account locking. If set, this option denies access in case that
# ldap attribute "pwdAccountLockedTime" is present and has value of
# '000001010000Z'. Please see the option 'ldap_pwdlockout_dn'. Please note that
# 'access_provider' in 'ldap' must be set for this feature to work. Please note
# that this option is superseded by the 'ppolicy' option and might be removed
# in a future release;
# ppolicy - use account locking. If set, this option denies access in case that
# ldap attribute "pwdAccountLockedTime" is present and has value of
# '000001010000Z' or represents any time in the past. The value of the
# "pwdAccountLockedTime" attribute must end with 'Z', which denotes the UTC time
# zone. Other time zones are not currently supported and will result in
# "access-denied" when users attempt to log in. Please see the option
# 'ldap_pwdlockout_dn'. Please note that 'access_provider' in 'ldap' must be set
# for this feature to work;
# expire - use 'ldap_account_expire_policy';
# pwd_expire_policy_reject, pwd_expire_policy_warn, pwd_expire_policy_renew -
# these options are useful if users are interested in being warned that
# password is about to expire and authentication is based on using a different
# method than passwords - for example SSH keys. The difference between these
# options is the action taken if user password is expired:
# pwd_expire_policy_reject - user is denied to log in, pwd_expire_policy_warn -
# user is still able to log in, pwd_expire_policy_renew - user is prompted to
# change his password immediately. Note If user password is expired no explicit
# message is prompted by SSSD. Please note that 'access_provider' in 'ldap' must
# be set for this feature to work. Also 'ldap_pwd_policy' must be set to an
# appropriate password policy;
# authorized_service - use the authorizedService attribute to determine access;
# host - use the host attribute to determine access;
# rhost - use the rhost attribute to determine whether remote host can access;
# Please note, rhost field in pam is set by application, it is better to check
# what the application sends to pam, before enabling this access control option.
        ldap_access_order:
        - 'filter'
# This option specifies the DN of password policy entry on LDAP server. Please
# note that absence of this option in sssd.conf in case of enabled account
# lockout checking will yield access denied as 'ppolicy' attributes on LDAP
# server cannot be checked properly. Default is
# 'cn=ppolicy,ou=policies,$ldap_search_base'.
        ldap_pwdlockout_dn: 'cn=ppolicy,ou=policies,dc=example,dc=com'
# Specifies how alias dereferencing is done when performing a search. The
# following options are allowed:
# never - aiases are never dereferenced;
# searching - aliases are dereferenced in subordinates of the base object, but
# not in locating the base object of the search;
# finding - aliases are only dereferenced when locating the base object of the
# search;
# always - aliases are dereferenced both in searching and in locating the base
# object of the search;
# Default is None (this is handled as never by the LDAP client libraries).
        ldap_deref: ''
# Allows to retain local users as members of an LDAP group for servers that use
# the RFC2307 schema. In some environments where the RFC2307 schema is used,
# local users are made members of LDAP groups by adding their names to the
# "memberUid" attribute. The self-consistency of the domain is compromised when
# this is done, so SSSD would normally remove the "missing" users from the
# cached group memberships as soon as nsswitch tries to fetch information about
# the user via getpw*() or initgroups() calls. This option falls back to
# checking if local users are referenced, and caches them so that later
# initgroups() calls will augment the local users with the additional LDAP
# groups. Default is 'false'.
        ldap_rfc2307_fallback_to_local_users: 'false'
# Specifies an upper limit on the number of entries that are downloaded during
# a wildcard lookup. At the moment, only the InfoPipe responder supports
# wildcard lookups. Default is '1000' (often the size of one page).
        wildcard_limit: '1000'
# How many seconds SSSD will wait between executing a full refresh of sudo
# rules (which downloads all rules that are stored on the server). The value
# must be greater than 'ldap_sudo_smart_refresh_interval'. Default is '21600'
# (6 hours).
        ldap_sudo_full_refresh_interval: '21600'
# How many seconds SSSD has to wait before executing a smart refresh of sudo
# rules (which downloads all rules that have USN higher than the highest server
# USN value that is currently known by SSSD). If USN attributes are not
# supported by the server, the modifyTimestamp attribute is used instead.
# Note: the highest USN value can be updated by three tasks:
# 1) by sudo full and smart refresh (if updated rules are found);
# 2) by enumeration of users and groups (if enabled and updated users or groups
# are found);
# 3) by reconnecting to the server (by default every 15 minutes, see
# 'ldap_connection_expire_timeout');
# Default is '900' (15 minutes).
        ldap_sudo_smart_refresh_interval: '900'
# If true, SSSD will download only rules that are applicable to this machine
# (using the IPv4 or IPv6 host/network addresses and hostnames). Default is
# 'true'.
        ldap_sudo_use_host_filter: 'true'
# List of hostnames or fully qualified domain names that should
# be used to filter the rules. If this option is empty, SSSD will try to
# discover the hostname and the fully qualified domain name automatically.
# If 'ldap_sudo_use_host_filter' is 'false' then this option has no effect.
# Default is None.
        ldap_sudo_hostnames:
        - 'ns1.example.com'
        - 'ns2.example.com'
# List of IPv4 or IPv6 host/network addresses that should be used to filter the
# rules. If this option is empty, SSSD will try to discover the addresses
# automatically. If 'ldap_sudo_use_host_filter' is 'false' then this option has
# no effect. Default is None.
        ldap_sudo_ip: ''
# If 'true' then SSSD will download every rule that contains a netgroup in
# "sudoHost" attribute. If 'ldap_sudo_use_host_filter' is 'false' then this
# option has no effect. Default is 'true'.
        ldap_sudo_include_netgroups: 'true'
# If true then SSSD will download every rule that contains a wildcard in
# "sudoHost" attribute. If 'ldap_sudo_use_host_filter' is 'false' then this
# option has no effect. Using wildcard is an operation that is very costly to
# evaluate on the LDAP server side! Default is 'false'.
        ldap_sudo_include_regexp: 'false'
# The name of the automount master map in LDAP. Default is 'auto.master'.
        ldap_autofs_map_master_name: 'auto.master'
# The object class of an automount map entry in LDAP.
# Default: 'nisMap' (rfc2307, when 'autofs_provider' in 'ad'), otherwise
# 'automountMap'.
        ldap_autofs_map_object_class: ''
# The name of an automount map entry in LDAP. Default is 'nisMapName' (rfc2307,
# when 'autofs_provider' in 'ad'), otherwise 'automountMapName'.
        ldap_autofs_map_name: ''
# The object class of an automount entry in LDAP. The entry usually corresponds
# to a mount point. Default is 'nisObject' (rfc2307, when 'autofs_provider' in
# 'ad'), otherwise 'automount'.
        ldap_autofs_entry_object_class: ''
# The key of an automount entry in LDAP. The entry usually corresponds to a
# mount point. Default is 'cn' (rfc2307, when 'autofs_provider' in 'ad'),
# otherwise 'automountKey'.
        ldap_autofs_entry_key: ''
# The key of an automount entry in LDAP. The entry usually corresponds to a
# mount point. Default is 'nisMapEntry' (rfc2307, when 'autofs_provider' in
# 'ad'), otherwise 'automountInformation'.
        ldap_autofs_entry_value: ''
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of "base", "onelevel" or
# "subtree". The filter must be a valid LDAP search filter as specified by
# RFC2254. Default is the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an Active
# Directory Server that might yield a large number of results and trigger the
# Range Retrieval extension in the response.
        ldap_netgroup_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of "base", "onelevel" or
# "subtree". The filter must be a valid LDAP search filter as specified by
# RFC2254. For examples of this syntax, please refer to the 'ldap_search_base'
# examples section. Default is the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an Active
# Directory Server that might yield a large number of results and trigger the
# Range Retrieval extension in the response.
        ldap_user_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of "base", "onelevel" or
# "subtree". The filter must be a valid LDAP search filter as specified by
# RFC2254. For examples of this syntax, please refer to the "ldap_search_base"
# examples section. Default: the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an
# Active Directory Server that might yield a large number of results and trigger
# the Range Retrieval extension in the response. If the option
# 'ldap_use_tokengroups' is enabled, the searches against Active Directory will
# not be restricted and return all groups memberships, even with no GID mapping.
# It is recommended to disable this feature, if group names are not being
# displayed correctly.
        ldap_group_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of "base", "onelevel" or
# "subtree". The filter must be a valid LDAP search filter as specified by
# RFC2254. For examples of this syntax, please refer to the "ldap_search_base"
# examples section. Default is the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an Active
# Directory Server that might yield a large number of results and trigger the
# Range Retrieval extension in the response.
        ldap_sudo_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# An optional base DN, search scope and LDAP filter to restrict LDAP searches
# for this attribute type. The scope can be one of "base", "onelevel" or
# "subtree". The filter must be a valid LDAP search filter as specified by
# RFC2254. For examples of this syntax, please refer to the "ldap_search_base"
# examples section. Default is the value of 'ldap_search_base'. Please note that
# specifying scope or filter is not supported for searches against an Active
# Directory Server that might yield a large number of results and trigger the
# Range Retrieval extension in the response.
        ldap_autofs_search_base: 'search_base[?scope?[filter][?search_base?scope?[filter]]*]'
# Time in milliseconds that sets how long would SSSD talk to a single DNS server
# before trying next one. Default is '1000'.
        dns_resolver_server_timeout: '1000'
# Time in seconds to tell how long would SSSD try to resolve single DNS query
# (e.g. resolution of a hostname or an SRV record) before trying the next
# hostname or discovery domain. Default: 2
        dns_resolver_op_timeout: '2'
# How long would SSSD try to resolve a failover service. This service resolution
# internally might include several steps, such as resolving DNS SRV queries or
# locating the site. Default is '4'.
        dns_resolver_timeout: '4'
# Specifies the lower bound of the range of POSIX IDs to use for mapping Active
# Directory user and group SIDs. This option is different from "min_id" in that
# "min_id" acts to filter the output of requests to this domain, whereas this
# option controls the range of ID assignment. This is a subtle distinction, but
# the good general advice would be to have "min_id" be less-than or equal to
# "ldap_idmap_range_min"./ Default is '200000'.
        ldap_idmap_range_min: '200000'
# Specifies the upper bound of the range of POSIX IDs to use for mapping Active
# Directory user and group SIDs. NOTE: This option is different from "max_id"
# in that "max_id" acts to filter the output of requests to this domain,
# whereas this option controls the range of ID assignment. This is a subtle
# distinction, but the good general advice would be to have "max_id" be
# greater-than or equal to "ldap_idmap_range_max". Default is '2000200000'.
        ldap_idmap_range_max: '2000200000'
# Specifies the number of IDs available for each slice. If the range size does
# not divide evenly into the min and max values, it will create as many complete
# slices as it can. The value of this option must be at least as large as the
# highest user RID planned for use on the Active Directory server. User lookups
# and login will fail for any user whose RID is greater than this value.
# For example, if your most recently-added Active Directory user has
# objectSid=S-1-5-21-2153326666-2176343378-3404031434-1107,
# "ldap_idmap_range_size" must be at least 1108 as range size is equal to
# maximal SID minus minimal SID plus one (e.g. 1108 = 1107 - 0 + 1). It is
# important to plan ahead for future expansion, as changing this value will
# result in changing all of the ID mappings on the system, leading to users
# with different local IDs than they previously had. Default is '200000'.
        ldap_idmap_range_size: '200000'
# Specify the domain SID of the default domain. This will guarantee that this
# domain will always be assigned to slice zero in the ID map, bypassing the
# murmurhash algorithm described above. Default is None.
        ldap_idmap_default_domain_sid: ''
# Specify the name of the default domain. Default is None.
        ldap_idmap_default_domain: ''
# Changes the behavior of the ID-mapping algorithm to behave more similarly to
# winbind's "idmap_autorid" algorithm. When this option is configured, domains
# will be allocated starting with slice zero and increasing monatomically with
# each additional domain. This algorithm is non-deterministic (it depends on the
# order that users and groups are requested). If this mode is required for
# compatibility with machines running winbind, it is recommended to also use
# the "ldap_idmap_default_domain_sid" option to guarantee that at least one
# domain is consistently allocated to slice zero. Default is 'false'.
        ldap_idmap_autorid_compat: 'false'
# Maximal number of secondary slices that is tried when performing mapping from
# UNIX id to SID. Note: Additional secondary slices might be generated when SID
# is being mapped to UNIX id and RID part of SID is out of range for secondary
# slices generated so far. If value of ldap_idmap_helper_table_size is equal to
# 0 then no additional secondary slices are generated. Default is '10'
        ldap_idmap_helper_table_size: '10'
# The object class of a user entry in LDAP. Default is 'posixAccount'.
        ldap_user_object_class: 'posixAccount'
# The LDAP attribute that corresponds to the user's login name. Default is 'uid'
# (rfc2307, rfc2307bis and IPA), 'sAMAccountName' (AD).
        ldap_user_name: 'uid'
# The LDAP attribute that corresponds to the user's id. Default is 'uidNumber'.
        ldap_user_uid_number: 'uidNumber'
# The LDAP attribute that corresponds to the user's primary group id. Default
# is 'gidNumber'.
        ldap_user_gid_number: 'gidNumber'
# Active Directory primary group attribute for ID-mapping. Note that this
# attribute should only be set manually if you are running the 'ldap' provider
# with ID mapping. Default is unset (LDAP), 'primaryGroupID' (AD).
        ldap_user_primary_group: ''
# The LDAP attribute that corresponds to the user's gecos field. Default is
# 'gecos'.
        ldap_user_gecos: 'gecos'
# The LDAP attribute that contains the name of the user's home directory.
# Default is 'homeDirectory' (LDAP and IPA), 'unixHomeDirectory' (AD).
        ldap_user_home_directory: 'homeDirectory'
# The LDAP attribute that contains the path to the user's default shell.
# Default is 'loginShell'.
        ldap_user_shell: 'loginShell'
# The LDAP attribute that contains the UUID/GUID of an LDAP user object.
# Default is not set in the general case, 'objectGUID' for AD and 'ipaUniqueID'
# for IPA.
        ldap_user_uuid: 'ipaUniqueID'
# The LDAP attribute that contains the objectSID of an LDAP user object. This is
# usually only necessary for ActiveDirectory servers. Default: 'objectSid' for
# ActiveDirectory, not set for other servers.
        ldap_user_objectsid: ''
# The LDAP attribute that contains timestamp of the last modification of the
# parent object. Default is 'modifyTimestamp'
        ldap_user_modify_timestamp: 'modifyTimestamp'
# When using ldap_pwd_policy=shadow, this parameter contains the name of an
# LDAP attribute corresponding to its shadow counterpart (date of the last
# password change). Default is 'shadowLastChange'.
        ldap_user_shadow_last_change: 'shadowLastChange'
# When using 'ldap_pwd_policy' in 'shadow', this parameter contains the name of
# an LDAP attribute corresponding to its shadow counterpart (minimum password
# age). Default is 'shadowMin'.
        ldap_user_shadow_min: 'shadowMin'
# When using 'ldap_pwd_policy' in 'shadow', this parameter contains the name of
# an LDAP attribute corresponding to its shadow counterpart (maximum password
# age). Default in 'shadowMax'.
        ldap_user_shadow_max: 'shadowMax'
# When using ldap_pwd_policy=shadow, this parameter contains the name of an
# LDAP attribute corresponding to its shadow counterpart (password warning
# period). Default is 'shadowWarning'.
        ldap_user_shadow_warning: 'shadowWarning'
# When using 'ldap_pwd_policy' in 'shadow', this parameter contains the name of
# an LDAP attribute corresponding to its shadow counterpart (password inactivity
# period). Default is 'shadowInactive'.
        ldap_user_shadow_inactive: 'shadowInactive'
# When using 'ldap_pwd_policy' in 'shadow' or 'ldap_account_expire_policy' in
# 'shadow', this parameter contains the name of an LDAP attribute corresponding
# to its shadow counterpart (account expiration date). Default in
# 'shadowExpire'.
        ldap_user_shadow_expire: 'shadowExpire'
# When using 'ldap_pwd_policy' in 'mit_kerberos', this parameter contains the
# name of an LDAP attribute storing the date and time of last password change
# in kerberos. Default is 'krbLastPwdChange'.
        ldap_user_krb_last_pwd_change: 'krbLastPwdChange'
# When using 'ldap_pwd_policy' in 'mit_kerberos', this parameter contains the
# name of an LDAP attribute storing the date and time when current password
# expires. Default is 'krbPasswordExpiration'.
        ldap_user_krb_password_expiration: 'krbPasswordExpiration'
# When using 'ldap_account_expire_policy' in 'ad', this parameter contains the
# name of an LDAP attribute storing the expiration time of the account.
# Default in 'accountExpires'.
        ldap_user_ad_account_expires: 'accountExpires'
# When using 'ldap_account_expire_policy' in 'ad', this parameter contains the
# name of an LDAP attribute storing the user account control bit field.
# Default is 'userAccountControl'.
        ldap_user_ad_user_account_control: 'userAccountControl'
# When using 'ldap_account_expire_policy' in 'rhds' or equivalent, this
# parameter determines if access is allowed or not. Default is 'nsAccountLock'.
        ldap_ns_account_lock: 'nsAccountLock'
# When using ldap_account_expire_policy=nds, this attribute determines if access
# is allowed or not. Default is 'loginDisabled'.
        ldap_user_nds_login_disabled: 'loginDisabled'
# When using 'ldap_account_expire_policy' in 'nds', this attribute determines
# until which date access is granted. Default is 'loginDisabled'.
        ldap_user_nds_login_expiration_time: ''
# When using 'ldap_account_expire_policy' in 'nds', this attribute determines
# the hours of a day in a week when access is granted. Default is
# 'loginAllowedTimeMap'.
        ldap_user_nds_login_allowed_time_map: 'loginAllowedTimeMap'
# The LDAP attribute that contains the user's Kerberos User Principal Name
# (UPN). Default is 'krbPrincipalName'.
        ldap_user_principal: 'krbPrincipalName'
# List of LDAP attributes that SSSD would fetch along with the usual set of user
# attributes. The list can either contain LDAP attribute names only, or
# colon-separated tuples of SSSD cache attribute name and LDAP attribute name.
# In case only LDAP attribute name is specified, the attribute is saved to the
# cache verbatim. Using a custom SSSD attribute name might be required by
# environments that configure several SSSD domains with different LDAP schemas.
# Please note that several attribute names are reserved by SSSD, notably the
# "name" attribute. SSSD would report an error if any of the reserved attribute
# names is used as an extra attribute name.
# Examples:
# 'ldap_user_extra_attrs' in 'telephoneNumber'.
# Save the "telephoneNumber" attribute from LDAP as "telephoneNumber" to the
# cache.
# 'ldap_user_extra_attrs' in 'phone:telephoneNumber'
# Save the "telephoneNumber" attribute from LDAP as "phone" to the cache.
# Default is None.
        ldap_user_extra_attrs: ''
# The LDAP attribute that contains the user's SSH public keys. Default is
# 'sshPublicKey'.
        ldap_user_ssh_public_key: 'sshPublicKey'
# The LDAP attribute that corresponds to the user's full name. Default is 'cn'.
        ldap_user_fullname: 'cn'
# The LDAP attribute that lists the user's group memberships. Default is
# 'memberOf'.
        ldap_user_member_of: 'memberOf'
# If 'access_provider' in 'ldap' and 'ldap_access_order' in
# 'authorized_service', SSSD will use the presence of the authorizedService
# attribute in the user's LDAP entry to determine access privilege. An explicit
# eny (!svc) is resolved first. Second, SSSD searches for explicit allow (svc)
# and finally for allow_all (*). Please note that the 'ldap_access_order'
# configuration option must include "authorized_service" in order for the
# 'ldap_user_authorized_service' option to work. Default is 'authorizedService'.
        ldap_user_authorized_service: 'authorizedService'
# If 'access_provider' in 'ldap' and 'ldap_access_order' in 'host', SSSD will
# use the presence of the host attribute in the user's LDAP entry to determine
# access privilege. An explicit deny (!host) is resolved first. Second, SSSD
# searches for explicit allow (host) and finally for allow_all (*). Please note
# that the 'ldap_access_order' configuration option must include "host" in order
# for the 'ldap_user_authorized_host' option to work. Default is 'host'.
        ldap_user_authorized_host: 'host'
# If 'access_provider' in 'ldap' and 'ldap_access_order' in 'rhost', SSSD will
# use the presence of the rhost attribute in the user's LDAP entry to determine
# access privilege. Similarly to host verification process.
# An explicit deny (!rhost) is resolved first. Second, SSSD searches for
# explicit allow (rhost) and finally for allow_all (*). Please note that the
# 'ldap_access_order' configuration option must include "rhost" in order for
# the 'ldap_user_authorized_rhost' option to work. Default is 'rhost'
        ldap_user_authorized_rhost: 'rhost'
# Name of the LDAP attribute containing the X509 certificate of the user.
# Default is 'userCertificate;binary'
        ldap_user_certificate: 'userCertificate;binary'
# Name of the LDAP attribute containing the email address of the user. If an
# email address of a user conflicts with an email address or fully qualified
# name of another user, then SSSD will not be able to serve those users
# properly. If for some reason several users need to share the same email
# address then set this option to a nonexistent attribute name in order to
# disable user lookup/login by email. Default is 'mail'.
        ldap_user_email: 'mail'
# The object class of a group entry in LDAP. Default is 'posixGroup'.
        ldap_group_object_class: 'posixGroup'
# The LDAP attribute that corresponds to the group name. Default is 'cn'
# (rfc2307, rfc2307bis and IPA), 'sAMAccountName' (AD).
        ldap_group_name: 'cn'
# The LDAP attribute that corresponds to the group's id. Default is 'gidNumber'.
        ldap_group_gid_number: 'gidNumber'
# The LDAP attribute that contains the names of the group's members. Default is
# 'memberuid' (rfc2307), 'member' (rfc2307bis).
        ldap_group_member: 'memberuid'
# The LDAP attribute that contains the UUID/GUID of an LDAP group object.
# Default: not set in the general case, 'objectGUID' for AD and 'ipaUniqueID'
# for IPA.
        ldap_group_uuid: 'objectGUID'
# The LDAP attribute that contains the objectSID of an LDAP group object. This
# is usually only necessary for ActiveDirectory servers. Default is 'objectSid'
# for ActiveDirectory, not set for other servers.
        ldap_group_objectsid: 'objectSid'
# The LDAP attribute that contains timestamp of the last modification of the
# parent object. Default is 'modifyTimestamp'.
        ldap_group_modify_timestamp: 'modifyTimestamp'
# The LDAP attribute that contains an integer value indicating the type of the
# group and maybe other flags. This attribute is currently only used by the AD
# provider to determine if a group is a domain local groups and has to be
# filtered out for trusted domains. Default is 'groupType' in the AD provider,
# otherwise not set.
        ldap_group_type: ''
# The LDAP attribute that references group members that are defined in an
# external domain. At the moment, only IPA's external members are supported.
# Default is 'ipaExternalMember' in the IPA provider, otherwise unset.
        ldap_group_external_member: ''
# The object class of a netgroup entry in LDAP. In IPA provider,
# ipa_netgroup_object_class should be used instead. Default is 'nisNetgroup'.
        ldap_netgroup_object_class: 'nisNetgroup'
# The LDAP attribute that corresponds to the netgroup name. In IPA provider,
# ipa_netgroup_name should be used instead. Default is 'cn'.
        ldap_netgroup_name: 'cn'
# The LDAP attribute that contains the names of the netgroup's members. In IPA
# provider, ipa_netgroup_member should be used instead. Default is
# 'memberNisNetgroup'.
        ldap_netgroup_member: 'memberNisNetgroup'
# The LDAP attribute that contains the (host, user, domain) netgroup triples.
# This option is not available in IPA provider. Default is 'nisNetgroupTriple'.
        ldap_netgroup_triple: 'nisNetgroupTriple'
# The LDAP attribute that contains timestamp of the last modification of the
# parent object. This option is not available in IPA provider.
# Default is 'modifyTimestamp'.
        ldap_netgroup_modify_timestamp: 'modifyTimestamp'
# The object class of a host entry in LDAP. Default is 'ipService'
        ldap_host_object_class: 'ipService'
# The LDAP attribute that corresponds to the host's name. Default is 'cn'.
        ldap_host_name: 'cn'
# The LDAP attribute that corresponds to the host's fully-qualified domain name.
# Default is 'fqdn'.
        ldap_host_fqdn: 'fqdn'
# The LDAP attribute that corresponds to the host's name. Default is
# 'serverHostname'.
        ldap_host_serverhostname: 'serverHostname'
# The LDAP attribute that lists the host's group memberships. Default is
# 'memberOf'.
        ldap_host_member_of: 'memberOf'
# The LDAP attribute that contains the host's SSH public keys. Default is
# 'sshPublicKey'.
        ldap_host_ssh_public_key: 'sshPublicKey'
# The LDAP attribute that contains the UUID/GUID of an LDAP host object.
# Default is None.
        ldap_host_uuid: ''
# The object class of a service entry in LDAP. Default is 'ipService'.
        ldap_service_object_class: ''
# The LDAP attribute that contains the name of service attributes and their
# aliases. Default is 'cn'.
         ldap_service_name: 'cn'
# The LDAP attribute that contains the port managed by this service.
# Default is 'ipServicePort'.
        ldap_service_port: 'ipServicePort'
# The LDAP attribute that contains the protocols understood by this service.
# Default is 'ipServiceProtocol'.
        ldap_service_proto: 'ipServiceProtocol'
# The object class of a sudo rule entry in LDAP. Default is 'sudoRole'.
        ldap_sudorule_object_class: 'sudoRole'
# The LDAP attribute that corresponds to the sudo rule name. Default is 'cn'.
        ldap_sudorule_name: 'cn'
# The LDAP attribute that corresponds to the command name. Default is
# 'sudoCommand'.
        ldap_sudorule_command: 'sudoCommand'
# The LDAP attribute that corresponds to the host name (or host IP address, host
# IP network, or host netgroup). Default is 'sudoHost'.
        ldap_sudorule_host: 'sudoHost'
# The LDAP attribute that corresponds to the user name (or UID, group name or
# user's netgroup). Default is 'sudoUser'.
        ldap_sudorule_user: 'sudoUser'
# The LDAP attribute that corresponds to the sudo options. Default is
# 'sudoOption'.
        ldap_sudorule_option: 'sudoOption'
# The LDAP attribute that corresponds to the user name that commands may be run
# as. Default is 'sudoRunAsUser'.
        ldap_sudorule_runasuser: 'sudoRunAsUser'
# The LDAP attribute that corresponds to the group name or group GID that
# commands may be run as. Default is 'sudoRunAsGroup'.
        ldap_sudorule_runasgroup: 'sudoRunAsGroup'
# The LDAP attribute that corresponds to the start date/time for when the sudo
# rule is valid. Default is 'sudoNotBefore'.
        ldap_sudorule_notbefore: 'sudoNotBefore'
# The LDAP attribute that corresponds to the expiration date/time, after which
# the sudo rule will no longer be valid. Default is 'sudoNotAfter'.
        ldap_sudorule_notafter: 'sudoNotAfter'
# The LDAP attribute that corresponds to the ordering index of the rule.
# Default is 'sudoOrder'.
        ldap_sudorule_order: 'sudoOrder'
# The object class of an iphost entry in LDAP. Default is 'ipHost'.
        ldap_iphost_object_class: 'ipHost'
# The LDAP attribute that contains the name of the IP host attributes and their
# aliases. Default is 'cn'.
        ldap_iphost_name: 'cn'
# The LDAP attribute that contains the IP host address. Default is
# 'ipHostNumber'.
        ldap_iphost_number: 'ipHostNumber'
# The object class of an ipnetwork entry in LDAP. Default is 'ipNetwork'.
        ldap_ipnetwork_object_class: 'ipNetwork'
# The LDAP attribute that contains the name of the IP network attributes and
# their aliases. Default is 'cn'.
        ldap_ipnetwork_name: 'cn'
# The LDAP attribute that contains the IP network address. Default is
# 'ipNetworkNumber'.
        ldap_ipnetwork_number: 'ipNetworkNumber'
# Specifies the name of the IPA domain. This is optional. If not provided, the
# configuration domain name is used.
        ipa_domain: ''
# List of IP addresses or hostnames of the IPA servers to which SSSD should
# connect in the order of preference. This is optional if autodiscovery is
# enabled.
        ipa_server: ''
        ipa_backup_server: ''
# Optional. May be set on machines where the hostname does not reflect the fully
# qualified name used in the IPA domain to identify this host. The hostname must
# be fully qualified.
        ipa_hostname: ''
# Optional. This option tells SSSD to automatically update the DNS server built
# into FreeIPA with the IP address of this client. The update is secured using
# GSS-TSIG. The IP address of the IPA LDAP connection is used for the updates,
# if it is not otherwise specified by using the 'dyndns_iface' option. While it
# is still possible to use the old ipa_dyndns_update option, users should
# migrate to using dyndns_update in their config file. Default is 'false'.
        dyndns_update: 'false'
# The TTL to apply to the client DNS record when updating it. If 'dyndns_update'
# is false this has no effect. This will override the TTL serverside if set by
# an administrator. While it is still possible to use the old 'ipa_dyndns_ttl'
# option, users should migrate to using dyndns_ttl in their config file.
# Default is '1200' (seconds).
        dyndns_ttl: '1200'
# Optional. Applicable only when 'dyndns_update' is true. Choose the interface
# or a list of interfaces whose IP addresses should be used for dynamic DNS
# updates. Special value "*" implies that IPs from all interfaces should be
# used. While it is still possible to use the old 'ipa_dyndns_iface' option,
# users should migrate to using dyndns_iface in their config file. Default is to
# use the IP addresses of the interface which is used for IPA LDAP connection.
        dyndns_iface:
        - 'em1'
        - 'vnet1'
        - 'vnet2'
# Whether the nsupdate utility should use GSS-TSIG authentication for secure
# updates with the DNS server, insecure updates can be sent by setting this
# option to 'none'. Default is 'GSS-TSIG'.
        dyndns_auth: ''
# Enables DNS sites - location based service discovery. If 'true' and service
# discovery (see Service Discovery paragraph at the bottom of the man page) is
# enabled, then the SSSD will first attempt location based discovery using a
# query that contains "_location.hostname.example.com" and then fall back to
# traditional SRV discovery. If the location based discovery succeeds, the IPA
# servers located with the location based discovery are treated as primary
# servers and the IPA servers located using the traditional SRV discovery are
# used as back up servers. Default is 'false'.
        ipa_enable_dns_sites: 'false'
# How often should the back end perform periodic DNS update in addition to the
# automatic update performed when the back end goes online. This option is
# optional and applicable only when 'dyndns_update' is 'true'. Default is '0'
# (disabled).
        dyndns_refresh_interval: '0'
# Whether the PTR record should also be explicitly updated when updating the
# client's DNS records. Applicable only when 'dyndns_update' is 'true'. This
# option should be False in most IPA deployments as the IPA server generates the
# PTR records automatically when forward records are changed. Default is 'false'
# (disabled).
        dyndns_update_ptr: 'false'
# Whether the nsupdate utility should default to using TCP for communicating
# with the DNS server. Default is 'false' (let nsupdate choose the protocol).
        dyndns_force_tcp: 'false'
# The DNS server to use when performing a DNS update. In most setups, it's
# recommended to leave this option unset. Setting this option makes sense for
# environments where the DNS server is different from the identity server.
# Please note that this option will be only used in fallback attempt when
# previous attempt using autodetected settings failed. Default is None (let
# nsupdate choose the server).
        dyndns_server: ''
# DNS update is by default performed in two steps - IPv4 update and then IPv6
# update. In some cases it might be desirable to perform IPv4 and IPv6 update
# in single step. Default is 'true'.
        dyndns_update_per_family: 'true'
# Optional. Use the given string as search base for Desktop Profile related
# objects. Default: Use base DN.
        ipa_deskprofile_search_base: ''
# Optional. Use the given string as search base for HBAC related objects.
# Default: Use base DN.
        ipa_hbac_search_base: ''
# Optional. Use the given string as search base for SELinux user maps.
# See 'ldap_search_base' for information about configuring multiple search
# bases. Default is the value of 'ldap_search_base'.
        ipa_selinux_search_base: ''
# Optional. Use the given string as search base for trusted domains. See
# 'ldap_search_base' for information about configuring multiple search bases.
# Default: the value of "cn=trusts,%basedn".
        ipa_subdomains_search_base: ''
# Optional. Use the given string as search base for master domain object.
# See 'ldap_search_base' for information about configuring multiple search
# bases. Default: the value of "cn=ad,cn=etc,%basedn".
        ipa_master_domain_search_base: ''
# Optional. Use the given string as search base for views containers.
# See 'ldap_search_base' for information about configuring multiple search
# bases. Default: the value of "cn=views,cn=accounts,%basedn".
        ipa_views_search_base: ''
# The name of the Kerberos realm. This is optional and defaults to the value of
# "ipa_domain". The name of the Kerberos realm has a special meaning in IPA - it
# is converted into the base DN to use for performing LDAP operations.
        krb5_realm: ''
# Absolute path of a directory where SSSD should place Kerberos configuration
# snippets. To disable the creation of the configuration snippets set the
# parameter to 'none'. Default: not set (krb5.include.d subdirectory of SSSD's
# pubconf directory).
        krb5_confd_path: ''
# The amount of time between lookups of the Desktop Profile rules against the
# IPA server. This will reduce the latency and load on the IPA server if there
# are many desktop profiles requests made in a short period.
# Default is '5' (seconds).
        ipa_deskprofile_refresh: '5'
# The amount of time between lookups of the Desktop Profile rules against the
# IPA server in case the last request did not return any rule. Default is
# '60' (minutes).
        ipa_deskprofile_request_interval: '60'
# The amount of time between lookups of the HBAC rules against the IPA server.
# This will reduce the latency and load on the IPA server if there are many
# access-control requests made in a short period. Default: 5 (seconds).
        ipa_hbac_refresh: '5'
# The amount of time between lookups of the SELinux maps against the IPA server.
# This will reduce the latency and load on the IPA server if there are many user
# login requests made in a short period. Default: 5 (seconds).
        ipa_hbac_selinux: '5'
# This option will be set by the IPA installer (ipa-server-install)
# automatically and denotes if SSSD is running on an IPA server or not. On an
# IPA server SSSD will lookup users and groups from trusted domains directly
# while on a client it will ask an IPA server. There are currently some
# assumptions that must be met when SSSD is running on an IPA server.
# The 'ipa_server' option must be configured to point to the IPA server itself.
# This is already the default set by the IPA installer, so no manual change is
# required. The 'full_name_format' option must not be tweaked to only print
# short names for users from trusted domains. Default is 'false'.
        ipa_server_mode: 'false'
# The automounter location this IPA client will be using. Default is the
# location named "default". Please note that the automounter only reads the
# master map on startup, so if any autofs-related changes are made to the
# sssd.conf, you typically also need to restart the automounter daemon after
# restarting the SSSD.
        ipa_automount_location: ''
# Objectclass of the view container. Default is 'nsContainer'.
        ipa_view_class: 'nsContainer'
# Name of the attribute holding the name of the view. Default: 'cn'.
        ipa_view_name: 'cn'
# Objectclass of the override objects. Default is 'ipaOverrideAnchor'.
        ipa_override_object_class: 'ipaOverrideAnchor'
# Name of the attribute containing the reference to the original object in a
# remote domain. Default is 'ipaAnchorUUID'.
        ipa_anchor_uuid: 'ipaAnchorUUID'
# Name of the objectclass for user overrides. It is used to determine if the
# found override object is related to a user or a group. User overrides can
# contain attributes given by:
# * ldap_user_name
# * ldap_user_uid_number
# * ldap_user_gid_number
# * ldap_user_gecos
# * ldap_user_home_directory
# * ldap_user_shell
# * ldap_user_ssh_public_key
# Default is 'ipaUserOverride'.
        ipa_user_override_object_class: 'ipaUserOverride'
# Name of the objectclass for group overrides. It is used to determine if the
# found override object is related to a user or a group. Group overrides can
# contain attributes given by
# * ldap_group_name
# * ldap_group_gid_number
# Default is 'ipaGroupOverride'.
        ipa_group_override_object_class: 'ipaGroupOverride'
# Specifies the name of the Active Directory domain. This is optional. If not
# provided, the configuration domain name is used. For proper operation, this
# option should be specified as the lower-case version of the long version of
# the Active Directory domain. The short domain name (also known as the
# NetBIOS or the flat name) is autodetected by the SSSD
        ad_domain: 'example.com'
# A list of enabled Active Directory domains. If provided, SSSD will ignore any
# domains not listed in this option. If left unset, all domains from the AD
# forest will be available. For proper operation, this option must be specified
# in all lower-case and as the fully qualified domain name of the Active
# Directory domain. Default is not set
        ad_enabled_domains:
          - 'sales.example.com'
          - 'eng.example.com'
# The list of hostnames of the AD servers to which SSSD should connect in order
# of preference. This is optional if autodiscovery is enabled. Trusted domains
# will always auto-discover servers even if the primary server is explicitly
# defined in the 'ad_server' option.
        ad_server: ''
        ad_backup_server: ''
# Optional. On machines where the hostname does not reflect the fully qualified
# name, sssd will try to expand the short name. If it is not possible or the
# short name should be really used instead, set this parameter explicitly. This
# field is used to determine the host principal in use in the keytab and to
# perform dynamic DNS updates. It must match the hostname for which the keytab
# was issued.
        ad_hostname: ''
# Enables DNS sites - location based service discovery. If true and service
# discovery is enabled, the SSSD will first attempt to discover the Active
# Directory server to connect to using the Active Directory Site Discovery and
# fall back to the DNS SRV records if no AD site is found. The DNS SRV
# configuration, including the discovery domain, is used during site discovery
# as well. Default is 'true'
        ad_enable_dns_sites: ''
# This option specifies LDAP access control filter that the user must match in
# order to be allowed access. Please note that the "access_provider" option must
# be explicitly set to "ad" in order for this option to have an effect. The
# option also supports specifying different filters per domain or forest. This
# extended filter would consist of: "KEYWORD:NAME:FILTER". The keyword can be
# either "DOM", "FOREST" or missing. If the keyword equals to "DOM" or is
# missing, then "NAME" specifies the domain or subdomain the filter applies to.
# If the keyword equals to "FOREST", then the filter equals to all domains from
# the forest specified by "NAME". Multiple filters can be separated with the
# "?"  character, similarly to how search bases work. Nested group membership
# must be searched for using a special OID ":1.2.840.113556.1.4.1941:" in
# addition to the full DOM:domain.example.org: syntax to ensure the parse
# does not attempt to interpret the colon characters associated with the OID.
# If you do not use this OID then nested group membership will not be resolved.
# The most specific match is always used. For example, if the option specified
# filter for a domain the user is a member of and a global filter, the
# per-domain filter would be applied. If there are more matches with the same
# specification, the first one is used. Default is not set.
        ad_access_filter: ''
# Specify AD site to which client should try to connect. If this option is not
# provided, the AD site will be auto-discovered. Default is not set
        ad_site: ''
# By default, the SSSD connects to the Global Catalog first to retrieve users
# from trusted domains and uses the LDAP port to retrieve group memberships or
# as a fallback. Disabling this option makes the SSSD only connect to the LDAP
# port of the current AD server. Please note that disabling Global Catalog
# support does not disable retrieving users from trusted domains. The SSSD
# would connect to the LDAP port of trusted domains instead. However, Global
# Catalog must be used in order to resolve cross-domain group memberships.
# Default is 'true'
        ad_enable_gc: ''
# This option specifies the operation mode for GPO-based access control
# functionality: whether it operates in 'disabled' mode, 'enforcing' mode, or
# 'permissive' mode. Please note that the "access_provider" option must be
# explicitly set to "ad" in order for this option to have an effect. GPO-based
# access control functionality uses GPO policy settings to determine whether or
# not a particular user is allowed to logon to the host. For more information
# on the supported policy settings please refer to the "ad_gpo_map" options.
# Please note that current version of SSSD does not support Active Directory's
# built-in groups. Built-in groups (such as Administrators with
# 'SID S-1-5-32-544') in GPO access control rules will be ignored by SSSD. See
# upstream issue tracker https://github.com/SSSD/sssd/issues/5063
# Before performing access control SSSD applies group policy security filtering
# on the GPOs. For every single user login, the applicability of the GPOs that
# are linked to the host is checked. In order for a GPO to apply to a user, the
# user or at least one of the groups to which it belongs must have following
# permissions on the GPO:
# Read: The user or one of its groups must have read access to the properties
# of the GPO (RIGHT_DS_READ_PROPERTY)
# Apply Group Policy: The user or at least one of its groups must be allowed to
# apply the GPO (RIGHT_DS_CONTROL_ACCESS).
# By default, the Authenticated Users group is present on a GPO and this group
# has both Read and Apply Group Policy access rights. Since authentication of a
# user must have been completed successfully before GPO security filtering and
# access control are started, the Authenticated Users group permissions on the
# GPO always apply also to the user. If the operation mode is set to enforcing,
# it is possible that users that were previously allowed logon access will now
# be denied logon access (as dictated by the GPO policy settings). In order to
# facilitate a smooth transition for administrators, a 'permissive' mode is
# available that will not enforce the access control rules, but will evaluate
# them and will output a syslog message if access would have been denied. By
# examining the logs, administrators can then make the necessary changes before
# setting the mode to enforcing. For logging GPO-based access control debug
# level 'trace functions' is required. There are three supported values for
# this option:
# 'disabled' - GPO-based access control rules are neither evaluated nor
# enforced
# 'enforcing' - GPO-based access control rules are evaluated and enforced
# 'permissive' - GPO-based access control rules are evaluated, but not enforced
# Instead, a syslog message will be emitted indicating that the user would have
# been denied access if this option's value were set to enforcing.
# Default: 'enforcing'
        ad_gpo_access_control: ''
# Normally when no applicable GPOs are found the users are allowed access. When
# this option is set to True users will be allowed access only when explicitly
# allowed by a GPO rule. Otherwise users will be denied access. This can be used
# to harden security but be careful when using this option because it can deny
# access even to users in the built-in Administrators group if no GPO rules
# apply to them. Default is 'false'
        ad_gpo_implicit_deny: ''
# Normally when some group policy containers (AD object) of applicable group
# policy objects are not readable by SSSD then users are denied access. This
# option allows to ignore group policy containers and with them associated
# policies if their attributes in group policy containers are not readable for
# SSSD. Default is 'false'
        ad_gpo_ignore_unreadable: ''
# A comma-separated list of PAM service names for which GPO-based access
# control is evaluated based on the InteractiveLogonRight and
# DenyInteractiveLogonRight policy settings. Only those GPOs are evaluated for
# which the user has Read and Apply Group Policy permission (see option
# 'ad_gpo_access_control'. If an evaluated GPO contains the deny interactive
# logon setting for the user or one of its groups, the user is denied local
# access. If none of the evaluated GPOs has an interactive logon right defined,
# the user is granted local access. If at least one evaluated GPO contains
# interactive logon right settings, the user is granted local access only, if
# it or at least one of its groups is part of the policy settings. Note: using
# the Group Policy Management Editor this value is called "Allow log on
# locally" and "Deny log on locally". It is possible to add another PAM service
# name to the default set by using "+service_name" or to explicitly remove a
# PAM service name from the default set by using "-service_name".
        ad_gpo_map_interactive: ''
# A comma-separated list of PAM service names for which GPO-based access control
# is evaluated based on the RemoteInteractiveLogonRight and
# DenyRemoteInteractiveLogonRight policy settings. Only those GPOs are
# evaluated for which the user has Read and Apply Group Policy permission
# (see option “ad_gpo_access_control”). If an evaluated GPO contains the deny
# remote logon setting for the user or one of its groups, the user is denied
# remote interactive access. If none of the evaluated GPOs has a remote
# interactive logon right defined, the user is granted remote access. If at
# least one evaluated GPO contains remote interactive logon right settings,
# the user is granted remote access only, if it or at least one of its groups
# is part of the policy settings. Using the Group Policy Management Editor this
# value is called "Allow log on through Remote Desktop Services" and
# "Deny log on through Remote Desktop Services".
        ad_gpo_map_remote_interactive: ''
# A comma-separated list of PAM service names for which GPO-based access control
# is evaluated based on the NetworkLogonRight and DenyNetworkLogonRight policy
# settings. Only those GPOs are evaluated for which the user has Read and Apply
# Group Policy permission (see option 'ad_gpo_access_control'). If an evaluated
# GPO contains the deny network logon setting for the user or one of its groups,
# the user is denied network logon access. If none of the evaluated GPOs has a
# network logon right defined, the user is granted logon access. If at least one
# evaluated GPO contains network logon right settings, the user is granted logon
# access only, if it or at least one of its groups is part of the policy
# settings. Note: Using the Group Policy Management Editor this value is called
# "Access this computer from the network" and "Deny access to this computer from
# the network".
        ad_gpo_map_network: ''
# A comma-separated list of PAM service names for which GPO-based access control
# is evaluated based on the BatchLogonRight and DenyBatchLogonRight policy
# settings. Only those GPOs are evaluated for which the user has Read and Apply
# Group Policy permission (see option 'ad_gpo_access_control'). If an evaluated
# GPO contains the deny batch logon setting for the user or one of its groups,
# the user is denied batch logon access. If none of the evaluated GPOs has a
# batch logon right defined, the user is granted logon access. If at least one
# evaluated GPO contains batch logon right settings, the user is granted logon
# access only, if it or at least one of its groups is part of the policy
# settings. Using the Group Policy Management Editor this value is called
# "Allow log on as a batch job" and "Deny log on as a batch job"
        ad_gpo_map_batch: ''
# A comma-separated list of PAM service names for which GPO-based access control
# is evaluated based on the ServiceLogonRight and DenyServiceLogonRight policy
# settings. Only those GPOs are evaluated for which the user has Read and Apply
# Group Policy permission (see option 'ad_gpo_access_control'). If an evaluated
# GPO contains the deny service logon setting for the user or one of its groups,
# the user is denied service logon access. If none of the evaluated GPOs has a
# service logon right defined, the user is granted logon access. If at least one
# evaluated GPO contains service logon right settings, the user is granted
# logon access only, if it or at least one of its groups is part of the policy
# settings. Note: Using the Group Policy Management Editor this value is called
# "Allow log on as a service" and "Deny log on as a service".
        ad_gpo_map_service: ''
# A comma-separated list of PAM service names for which GPO-based access is
# always granted, regardless of any GPO Logon Rights.
        ad_gpo_map_permit: ''
# A comma-separated list of PAM service names for which GPO-based access is
# always denied, regardless of any GPO Logon Rights. Default is not set
        ad_gpo_map_deny: ''
# This option defines how access control is evaluated for PAM service names that
# are not explicitly listed in one of the ad_gpo_map_* options. This option can
# be set in two different manners. First, this option can be set to use a
# default logon right. For example, if this option is set to 'interactive', it
# means that unmapped PAM service names will be processed based on the
# InteractiveLogonRight and DenyInteractiveLogonRight policy settings.
# Alternatively, this option can be set to either always permit or always deny
# access for unmapped PAM service names
# Supported values for this option include:
# 'interactive'
# 'remote_interactive'
# 'network'
# 'batch'
# 'service'
# 'permit'
# 'deny' (the default)
        ad_gpo_default_right: 'true'
# SSSD will check once a day if the machine account password is older than the
# given age in days and try to renew it. A value of 0 will disable the renewal
# attempt. Default is '30' days
        ad_maximum_machine_account_password_age: ''
# This option should only be used to test the machine account renewal task. The
# option expects 2 integers separated by a colon (':'). The first integer
# defines the interval in seconds how often the task is run. The second
# specifies the initial timeout in seconds before the task is run for the first
# time after startup. Default is '86400:750' (24h and 15m)
        ad_machine_account_password_renewal_opts: ''
# If enabled, when SSSD renews the machine account password, it will also be
# updated in Samba's database. This prevents Samba's copy of the machine account
# password from getting out of date when it is set up to use AD for
# authentication. Default is 'false'
        ad_update_samba_machine_account_password: ''
# By default SSSD uses the plain LDAP port 389 and the Global Catalog port 3628.
# If this option is set to True SSSD will use the LDAPS port 636 and Global
# Catalog port 3629 with LDAPS protection. Since AD does not allow to have
# multiple encryption layers on a single connection and we still want to use
# SASL/GSSAPI or SASL/GSS-SPNEGO for authentication the SASL security property
# maxssf is set to 0 (zero) for those connections. Default is 'false'
        ad_use_ldaps: ''
# If this option is set to 'true' SSSD will not filter out Domain Local groups
# from remote domains in the AD forest. By default they are filtered out e.g.
# when following a nested group hierarchy in remote domains because they are
# not valid in the local domain. To be compatible with other solutions which
# make AD users and groups available on Linux client this option was added.
# Please note that setting this option to 'true will be against the intention
# of Domain Local group in Active Directory and SHOULD ONLY BE USED TO
# FACILITATE MIGRATION FROM OTHER SOLUTIONS. Although the group exists and user
# can be member of the group the intention is that the group should be only
# used in the domain it is defined and in no others. Since there is only one
# type of POSIX groups the only way to achieve this on the Linux side is to
# ignore those groups. This is also done by Active Directory as can be seen in
# the PAC of the Kerberos ticket for a local service or in tokenGroups requests
# where remote Domain Local groups are missing as well. Given the comments
# above, if this option is set to 'true' the tokenGroups request must be
# disabled by setting 'ldap_use_tokengroups' to 'false' to get consistent
# group-memberships of a users. Additionally the Global Catalog lookup should
# be skipped as well by setting 'ad_enable_gc' to 'false'. Finally it might be
# necessary to modify 'ldap_group_nesting_level' if the remote Domain Local
# groups can only be found with a deeper nesting level. Default is 'false'
        ad_allow_remote_domain_local_groups: ''
# Default regular expression that describes how to parse the string containing
# user name and domain into these components. Each domain can have an individual
# regular expression configured. For some ID providers there are also default
# regular expressions.
      re_expression: ''
# A printf-compatible format that describes how to compose a fully qualified
# name from user name and domain name components. The following expansions are
# supported:
# - %1$s - user name;
# - %2$s - domain name as specified in the SSSD config file;
# - %3$s - domain flat name. Mostly usable for Active Directory domains, both
# directly configured or discovered via IPA trusts.
# Each domain can have an individual format string configured.
      full_name_format: ''
# Controls if SSSD should monitor the state of resolv.conf to identify when it
# needs to update its internal DNS resolver. Default is 'true'.
      monitor_resolv_conf: 'true'
# By default, SSSD will attempt to use inotify to monitor configuration files
# changes and will fall back to polling every five seconds if inotify cannot be
# used.
# There are some limited situations where it is preferred that we should skip
# even trying to use inotify. In these rare cases, this option should be set to
# 'false'. Default 'true' on platforms where inotify is supported. False on
# other platforms. This option will have no effect on platforms where inotify is
# unavailable. On these platforms, polling will always be used.
      try_inotify: 'true'
# Directory on the filesystem where SSSD should store Kerberos replay cache
# files. This option accepts a special value __LIBKRB5_DEFAULTS__ that will
# instruct SSSD to let libkrb5 decide the appropriate location for the replay
# cache. By default is distribution-specific and specified at build-time
# (__LIBKRB5_DEFAULTS__ if not configured).
      krb5_rcache_dir: ''
# The user to drop the privileges to where appropriate to avoid running as the
# root user. This option does not work when running socket-activated services,
# as the user set up to run the processes is set up during compilation time.
# The way to override the systemd unit files is by creating the appropriate
# files in /etc/systemd/system/. Keep in mind that any change in the socket
# user, group or permissions may result in a non-usable SSSD. The same may
# occur in case of changes of the user running the NSS responder. When not set
# process will run as root (the default).
      user: ''
# This string will be used as a default domain name for all names without a
# domain name component. The main use case is environments where the primary
# domain is intended for managing host policies and all users are located in a
# trusted domain. The option allows those users to log in just with their user
# name without giving a domain name as well. Please note that if this option is
# set all users from the primary domain have to use their fully qualified name,
# e.g. user@domain.name, to log in. Setting this option changes default of
# use_fully_qualified_names to True. It is not allowed to use this option
# together with 'use_fully_qualified_names' set to 'false' One exception from
# this rule are domains with 'id_provider' in 'files' that always try to match
# the behaviour of 'nss_files' and therefore their output is not qualified even
# when the 'default_domain_suffix' option is used. Default is None.
      default_domain_suffix: ''
# This parameter will replace spaces (space bar) with the given character for
# user and group names. e.g. (_). User name "john doe" will be "john_doe". This
# feature was added to help compatibility with shell scripts that have
# difficulty handling spaces, due to the default field separator in the shell.
# Please note it is a configuration error to use a replacement character that
# might be used in user or group names. If a name contains the replacement
# character SSSD tries to return the unmodified name but in general the result
# of a lookup is undefined. Default is not set (spaces will not be replaced).
      override_space: ''
# With this parameter the certificate verification can be tuned with a list of
# options. Supported options are:
# - no_ocsp - disables Online Certificate Status Protocol (OCSP) checks. This
# might be needed if the OCSP servers defined in the certificate are not
# reachable from the client.
# - soft_ocsp - (NSS Version) This option is ignored.
# (OpenSSL Version) If a connection cannot be established to an OCSP responder
# the OCSP check is skipped. This option should be used to allow authentication
# when the system is offline and the OCSP responder cannot be reached.
# - ocsp_dgst - digest (hash) function used to create the certificate ID for the
# OCSP request. Allowed values are: 'sha1', 'sha256' (the default), 'sha384',
# 'sha512'.
# - no_verification - disables verification completely. This option should only
# be used for testing.
# ocsp_default_responder=URL - sets the OCSP default responder which should be
# used instead of the one mentioned in the certificate. URL must be replaced
# with the URL of the OCSP default responder e.g. http://example.com:80/ocsp.
# (NSS Version) This option must be used together with
# - 'ocsp_default_responder_signing_cert'.
# ocsp_default_responder_signing_cert=NAME - (NSS Version) the nickname of the
# cert to trust (expected) to sign the OCSP responses. The certificate with the
# given nickname must be available in the systems NSS database. This option must
# be used together with 'ocsp_default_responder'. (OpenSSL version) This option
# is currently ignored. All needed certificates must be available in the PEM
# file given by 'pam_cert_db_path'.
# - crl_file=/PATH/TO/CRL/FILE - (NSS Version) this option is ignored, please
# see crlutil how to import a Certificate Revocation List (CRL) into a NSS
# database.
# (OpenSSL Version) use the Certificate Revocation List (CRL) from the given
# file during the verification of the certificate. The CRL must be given in PEM
# format, see crl(1ssl) for details.
# - soft_crl - (NSS Version) this option is ignored.
# (OpenSSL Version) If a Certificate Revocation List (CRL) is expired ignore
# the CRL checks for the related certificates. This option should be used to
# allow authentication when the system is offline and the CRL cannot be renewed.
# This man page was generated for the NSS version. Unknown options are reported
# but ignored. Default: not set, i.e. do not restrict certificate verification.
      certificate_verification: ''
# SSSD hooks into the netlink interface to monitor changes to routes, addresses,
# links and trigger certain actions. The SSSD state changes caused by netlink
# events may be undesirable and can be disabled by setting this option to
# 'true'. Default is 'false' (netlink changes are detected).
      disable_netlink: 'false'
# When this option is enabled, SSSD prepends an implicit domain with
# 'id_provider=files' before any explicitly configured domains. Default is
# 'false'.
      enable_files_domain: 'false'
# List of domains and subdomains representing the lookup order that will be
# followed. The list doesn't have to include all possible domains as the missing
# domains will be looked up based on the order they're presented in the
# "domains" configuration option. The subdomains which are not listed as part
# of "lookup_order" will be looked up in a random order for each parent
# domain. Please, note that when this option is set the output format of all
# commands is always fully-qualified even when using short names for input, for
# all users but the ones managed by the files provider. In case the
# administrator wants the output not fully-qualified, the 'full_name_format'
# option can be used as shown below: "full_name_format=%1$s" However, keep in
# mind that during login, login applications often canonicalize the username by
# calling getpwnam which, if a shortname is returned for a qualified input
# (while trying to reach a user which exists in multiple domains) might re-route
# the login attempt into the domain which uses shortnames, making this
# workaround totally not recommended in cases where usernames may overlap
# between domains. Default is None.
      domain_resolution_order: ''
    nss:
# How many seconds should nss_sss cache enumerations (requests for info about
# all users). Default is 120.
    - enum_cache_timeout: '120'
# The entry cache can be set to automatically update entries in the background
# if they are requested beyond a percentage of the entry_cache_timeout value
# for the domain. For example, if the domain's 'entry_cache_timeout' is set to
# '30s' and 'entry_cache_nowait_percentage' is set to '50' (percent), entries
# that come in after 15 seconds past the last cache update will be returned
# immediately, but the SSSD will go and update the cache on its own, so that
# future requests will not need to block waiting for a cache update. Valid
# values for this option are 0-99 and represent a percentage of the
# 'entry_cache_timeout' for each domain. For performance reasons, this
# percentage will never reduce the nowait timeout to less than 10 seconds.
# Default is '50', '0' disables this feature.
      entry_cache_nowait_percentage: '50'
# Specifies for how many seconds nss_sss should cache negative cache hits (that
# is, queries for invalid database entries, like nonexistent ones) before asking
# the back end again. Default is '15'.
      entry_negative_timeout: '15'
# Specifies for how many seconds nss_sss should keep local users and groups in
# negative cache before trying to look it up in the back end again. Setting the
# option to 0 disables this feature. Default is '14400' (4 hours).
      local_negative_timeout: '14400'
# Exclude certain users or groups from being fetched from the sss NSS database.
# This is particularly useful for system accounts. This option can also be set
# per-domain or include fully-qualified names to filter only users from the
# particular domain or by a user principal name (UPN). The 'filter_groups'
# option doesn't affect inheritance of nested group members, since filtering
# happens after they are propagated for returning via NSS. E.g. a group having
# a member group filtered out will still have the member users of the latter
# listed. Default is 'root'.
      filter_users: 'root'
      filter_groups: 'root'
# If you want filtered user still be group members set this option to 'false'.
# Default is 'true'.
      filter_users_in_groups: 'true'
# Override the user's home directory. You can either provide an absolute value
# or a template. In the template, the following sequences are substituted:
# %u - login name;
# %U - UID number;
# %d - domain name;
# %f - fully qualified user name (user@domain);
# %l - the first letter of the login name;
# %P - UPN - User Principal Name (name@REALM);
# %o - the original home directory retrieved from the identity provider;
# %H - the value of configure option homedir_substring;
# %% - a literal '%';
# This option can also be set per-domain. Default is not set (SSSD will use the
# value retrieved from LDAP).
      override_homedir: '/home/%u'
# The value of this option will be used in the expansion of the
# override_homedir option if the template contains the format string %H. An
# LDAP directory entry can directly contain this template so that this option
# can be used to expand the home directory path for each client machine (or
# operating system). It can be set per-domain or globally in the 'nss' section.
# A value specified in a domain section will override one set in the [nss]
# section. Default is '/home'.
      homedir_substring: '/home'
# Set a default template for a user's home directory if one is not specified
# explicitly by the domain's data provider. The available values for this option
# are the same as for 'override_homedir'. Default is None.
      fallback_homedir: '/home/%u'
# Override the login shell for all users. This option supersedes any other shell
# options if it takes effect and can be set either in the 'nss' section or
# per-domain. Default: not set (SSSD will use the value retrieved from LDAP).
      override_shell: ''
# Restrict user shell to one of the listed values. The order of evaluation is:
# 1. If the shell is present in '/etc/shells', it is used.
# 2. If the shell is in the 'allowed_shells' list but not in '/etc/shells', use
# the value of the 'shell_fallback' parameter.
# 3. If the shell is not in the 'allowed_shells' list and not in '/etc/shells',
# a nologin shell is used.
# The wildcard ('*') can be used to allow any shell. The ('*') is useful if you
# want to use 'shell_fallback' in case that user's shell is not in '/etc/shells'
# and maintaining list of all allowed shells in 'allowed_shells' would be to
# much overhead. An empty string for shell is passed as-is to libc. The
# '/etc/shells' is only read on SSSD start up, which means that a restart of the
# SSSD is required in case a new shell is installed. Default is None. The user
# shell is automatically used.
      allowed_shells: ''
# Replace any instance of these shells with the 'shell_fallback'.
      vetoed_shells: ''
# The default shell to use if an allowed shell is not installed on the machine.
# Default is '/bin/sh'.
      shell_fallback: '/bin/sh'
# The default shell to use if the provider does not return one during lookup.
# This option can be specified globally in the 'nss' section or per-domain.
# Default is None (return NULL if no shell is specified and rely on libc to
# substitute something sensible when necessary, usually /bin/sh).
      default_shell: ''
# Specifies time in seconds for which the list of subdomains will be considered
# valid. Default is '60'.
      get_domains_timeout: '60'
# Specifies time in seconds for which records in the in-memory cache will be
# valid. Setting this option to zero will disable the in-memory cache. Default
# is '300'. WARNING: Disabling the in-memory cache will have significant
# negative impact on SSSD's performance and should only be used for testing.
# NOTE: If the environment variable 'SSS_NSS_USE_MEMCACHE' is set to 'NO',
# client applications will not use the fast in-memory cache.
      memcache_timeout: '300'
# Some of the additional NSS responder requests can return more attributes than
# just the POSIX ones defined by the NSS interface. The list of attributes is
# controlled by this option. It is handled the same way as the 'user_attributes'
# option of the InfoPipe responder (see sssd-ifp for details) but with no
# default values. To make configuration more easy the NSS responder will check
# the InfoPipe option if it is not set for the NSS responder. Default is None,
# fallback to InfoPipe option.
      user_attributes: ''
# The value that NSS operations that return users or groups will return for the
# 'password' field. This option can also be set per-domain. Default is '*'
# (remote domains) or 'x' (the files domain)
      pwfield: ''
# These options can be used to configure the Pluggable Authentication Module
# (PAM) service.
    pam:
# If the authentication provider is offline, how long should we allow cached
# logins (in days since the last successful online login). Default is '0' (no
# imit).
    - offline_credentials_expiration:
# If the authentication provider is offline, how many failed login attempts are
# allowed. Default: 0 (No limit)
      offline_failed_login_attempts: '0'
# The time in minutes which has to pass after 'offline_failed_login_attempts'
# has been reached before a new login attempt is possible. If set to '0' the
# user cannot authenticate offline if 'offline_failed_login_attempts' has been
# reached. Only a successful online authentication can enable offline
# authentication again. Default is '5'.
      offline_failed_login_delay: '5'
# Controls what kind of messages are shown to the user during authentication.
# The higher the number to more messages are displayed. Currently sssd supports
# the following values:
# 0 - do not show any message (the default);
# 1 - show only important messages;
# 2 - show informational messages;
# 3 - show all messages and debug information;
      pam_verbosity: '0'
# A ist of strings which allows to remove (filter) data sent by the PAM
# responder to pam_sss PAM module. There are different kind of responses sent to
# pam_sss e.g. messages displayed to the user or environment variables which
# should be set by pam_sss. While messages already can be controlled with the
# help of the pam_verbosity option this option allows to filter out other kind
# of responses as well. Currently the following filters are supported:
# ENV - do not send any environment variables to any service.
# ENV:var_name - do not send environment variable var_name to any service.
# ENV:var_name:service - do not send environment variable var_name to service.
# Default is not set.
      pam_response_filter: 'ENV:KRB5CCNAME:sudo-i'
# For any PAM request while SSSD is online, the SSSD will attempt to immediately
# update the cached identity information for the user in order to ensure that
# authentication takes place with the latest information. A complete PAM
# conversation may perform multiple PAM requests, such as account management
# and session opening. This option controls (on a per-client-application basis)
# how long (in seconds) we can cache the identity information to avoid
# excessive round-trips to the identity provider. Default is '5'.
      pam_id_timeout: '5'
# Display a warning N days before the password expires. Please note that the
# backend server has to provide information about the expiration time of the
# password. If this information is missing, sssd cannot display a warning. If
# zero is set, then this filter is not applied, i.e. if the expiration warning
# was received from backend server, it will automatically be displayed. This
# setting can be overridden by setting pwd_expiration_warning for a particular
# domain. Default is '0'.
      pam_pwd_expiration_warning: '0'
# Specifies time in seconds for which the list of subdomains will be considered
# valid. Default is '60'.
      get_domains_timeout: '60'
# Specifies the list of UID values or user names that are allowed to run PAM
# conversations against trusted domains. Users not included in this list can
# only access domains marked as public with 'pam_public_domains'. User names are
# resolved to UIDs at startup. Default is all users are considered trusted by
# default. Please note that UID 0 is always allowed to access the PAM responder
# even in case it is not in the pam_trusted_users list.
      pam_trusted_users: ''
# Specifies the list of domain names that are accessible even to untrusted
# users. Two special values for 'pam_public_domains' option are defined:
# 'all' - untrusted users are allowed to access all domains in PAM responder;
# 'none' - untrusted users are not allowed to access any domains PAM in
# responder (the default).
      pam_public_domains: 'none'
# Allows a custom expiration message to be set, replacing the default
# "Permission denied" message. Please be aware that message is only printed for
# the SSH service unless 'pam_verbosity' is set to '3' (show all messages and
# debug information). Default is None.
      pam_account_expired_message: 'Account expired, please contact help desk.'
# Allows a custom lockout message to be set, replacing the default
# "Permission denied" message.
      pam_account_locked_message: 'Account locked, please contact help desk.'
# Enable certificate based Smartcard authentication. Since this requires
# additional communication with the Smartcard which will delay the
# authentication process this option is disabled by default. Default is 'false'.
      pam_cert_auth: 'false'
# The path to the certificate database.
# Default is:
# * '/etc/pki/nssdb' - NSS version, path to a NSS database which contains the
# PKCS#11 modules to access the Smartcard and the trusted CA certificates);
# * '/etc/sssd/pki/sssd_auth_ca_db.pem' - OpenSSL version, path to a file with
# trusted CA certificates in PEM format;
      pam_cert_db_path: ''
# How many seconds will pam_sss wait for p11_child to finish. Default is '10'.
      p11_child_timeout: '10'
# Which PAM services are permitted to contact domains of type "application".
# Default is None.
      pam_app_services: ''
# A list of PAM service names for which it will be allowed to use Smartcards.
# It is possible to add another PAM service name to the default set by using
# "+service_name" or to explicitly remove a PAM service name from the default
# set by using "-service_name". For example, in order to replace a default PAM
# service name for authentication with Smartcards (e.g. "login") with a custom
# PAM service name (e.g. "my_pam_service"), you would use the following
# configuration:
# pam_p11_allowed_services:
#  - '+my_pam_service'
#  - '-login'
# Default: the default set of PAM service names includes:
# 'login'
# 'su'
# 'su-l'
# 'gdm-smartcard'
# 'gdm-password'
# 'kdm'
# 'sudo'
# 'sudo-i'
# 'gnome-screensaver'
      pam_p11_allowed_services: ''
# If Smartcard authentication is required how many extra seconds in addition to
# 'p11_child_timeout' should the PAM responder wait until a Smartcard is
# inserted. Default is '60'.
      p11_wait_for_card_timeout: '60'
# PKCS#11 URI (see RFC-7512 for details) which can be used to restrict the
# selection of devices used for Smartcard authentication. By default SSSD's
# 'p11_child' will search for a PKCS#11 slot (reader) where the "removable"
# flags is set and read the certificates from the inserted token from the first
# slot found. If multiple readers are connected 'p11_uri' can be used to tell
# 'p11_child' to use a specific reader. Example:
# p11_uri: 'slot-description=My%20Smartcard%20Reader'
# or
# p11_uri: 'library-description=OpenSC%20smartcard%20framework;slot-id=2'
# To find suitable URI please check the debug output of p11_child. As an
# alternative the GnuTLS utility p11tool with e.g. the "--list-all" will show
# PKCS#11 URIs as well. Default is None.
      p11_uri: ''
# The PAM responder can force an online lookup to get the current group
# memberships of the user trying to log in. This option controls when this
# should be done and the following values are allowed:
# 'always' - always do an online lookup, please note that pam_id_timeout still
# applies;
# 'no_session' - only do an online lookup if there is no active session of the
# user, i.e. if the user is currently not logged in (the default);
# 'never' - never force an online lookup, use the data from the cache as long as
# they are not expired;
      pam_initgroups_scheme: 'no_session'
    sudo:
# Whether or not to evaluate the sudoNotBefore and sudoNotAfter attributes that
# implement time-dependent sudoers entries. Default is 'false'.
    - sudo_timed: 'false'
# Maximum number of expired rules that can be refreshed at once. If number of
# expired rules is below threshold, those rules are refreshed with
# "rules refresh" mechanism. If the threshold is exceeded a "full refresh" of
# sudo rules is triggered instead. This threshold number also applies to IPA
# sudo command and command group searches. Default is '50'.
      sudo_threshold: '50'
    autofs:
# Specifies for how many seconds should the autofs responder negative cache
# hits (that is, queries for invalid map entries, like nonexistent ones) before
# asking the back end again. Default is '15'. Please note that the automounter
# only reads the master map on startup, so if any autofs-related changes are
# made to the sssd.conf, you typically also need to restart the automounter
# daemon after restarting the SSSD.
    - autofs_negative_timeout: '15'
    ssh:
# Whether or not to hash host names and addresses in the managed known_hosts
# file. Default is 'true'.
    - ssh_hash_known_hosts: 'true'
# How many seconds to keep a host in the managed known_hosts file after its
# host keys were requested. Default is '180'.
      ssh_known_hosts_timeout: '180'
# If set to true the sss_ssh_authorizedkeys will return ssh keys derived from
# the public key of X.509 certificates stored in the user entry as well.
# Default is 'true'.
      ssh_use_certificate_keys: 'true'
# By default the ssh responder will use all available certificate matching
# rules to filter the certificates so that ssh keys are only derived from the
# matching ones. With this option the used rules can be restricted with a comma
# separated list of mapping and matching rule names. All other rules will be
# ignored. There are two special key words 'all_rules' and 'no_rules' which will
# enable all or no rules, respectively. The latter means that no certificates
# will be filtered out and ssh keys will be generated from all valid
# certificates. If no rules are configured using 'all_rules' will enable a
# default rule which enables all certificates suitable for client
# authentication. This is the same behavior as for the PAM responder if
# certificate authentication is enabled. A non-existing rule name is considered
# an error. If as a result no rule is selected all certificates will be ignored.
# Default is None, equivalent to 'all_rules, all found rules or the default rule
# are used.
      ssh_use_certificate_matching_rules: ''
# Path to a storage of trusted CA certificates. The option is used to validate
# user certificates before deriving public ssh keys from them. Default:
# * '/etc/pki/nssdb' - NSS version, path to a NSS database.
# * '/etc/sssd/pki/sssd_auth_ca_db.pem' - OpenSSL version, path to a file with
# trusted CA certificates in PEM format.
      ca_db: ''
# The PAC responder works together with the authorization data plugin for MIT
# Kerberos sssd_pac_plugin.so and a sub-domain provider. The plugin sends the
# PAC data during a GSSAPI authentication to the PAC responder. The sub-domain
# provider collects domain SID and ID ranges of the domain the client is joined
# to and of remote trusted domains from the local domain controller. If the PAC
# is decoded and evaluated some of the following operations are done:
# * If the remote user does not exist in the cache, it is created. The UID is
# determined with the help of the SID, trusted domains will have UPGs and the
# GID will have the same value as the UID. The home directory is set based on
# the subdomain_homedir parameter. The shell will be empty by default, i.e. the
# system defaults are used, but can be overwritten with the 'default_shell'
# parameter.
# * If there are SIDs of groups from domains sssd knows about, the user will be
# added to those groups.
    pac:
# Specifies the list of UID values or user names that are allowed to access the
# PAC responder. User names are resolved to UIDs at startup. Default is '0'
# (only the root user is allowed to access the PAC responder). Please note that
# although the UID 0 is used as the default it will be overwritten with this
# option. If you still want to allow the root user to access the PAC responder,
# which would be the typical case, you have to add 0 to the list of allowed
# UIDs as well.
    - allowed_uids: '0'
# Lifetime of the PAC entry in seconds. As long as the PAC is valid the PAC
# data can be used to determine the group memberships of a user. Default is 300.
      pac_lifetime: '300'
    session_recording:
# One of the following strings specifying the scope of session recording:
# 'none' - no users are recorded (the default);
# 'some' - users/groups specified by users and groups options are recorded;
# 'all' - all users are recorded;
    - scope: 'none'
# A list of users which should have session recording enabled. Matches user
# names as returned by NSS. I.e. after the possible space replacement, case
# changes, etc. Default is None - matches no users.
      users: ''
# A list of groups, members of which should have session recording enabled.
# Matches group names as returned by NSS. I.e. after the possible space
# replacement, case changes, etc. Using this option (having it set to anything)
# has a considerable performance cost, because each uncached request for a user
# requires retrieving and matching the groups the user is member of. Default is
# None - matches no groups.
      groups: ''
```

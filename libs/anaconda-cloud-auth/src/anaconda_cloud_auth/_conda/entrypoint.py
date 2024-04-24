# The plugin entrypoints are loaded via this module as specified in pyproject.toml
# We do this to be very conservative and catch potential import errors without surfacing to users.
# Plugins were first introduced in conda=22.11.0
# The ChannelAuthBase class was introduced in conda=23.7.0
try:
    from anaconda_cloud_auth._conda import plugins  # noqa: F401
except ImportError:
    pass

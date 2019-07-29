import six

if six.PY2:
    from cloudmesh.config.v2.config import Config, Active
else:
    from cloudmesh.config.v3.config import Config, Active

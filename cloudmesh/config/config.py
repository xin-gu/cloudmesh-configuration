import six

if six.PY2:
    import cloudmesh.confif.v2
    from cloudmesh.config.v2.config import Config, Active
else:
    from cloudmesh.config.v3.config import Config, Active

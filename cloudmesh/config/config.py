
if six.PY2:
    from cloudmesh.config.v2.config import Config
else:
    from cloudmesh.config.v3.config import Config, Active

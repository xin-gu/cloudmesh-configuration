"""
cloudmesh name space.
"""
import pkg_resources
import six

pkg_resources.declare_namespace(__name__)

if six.PY2:
    from cloudmesh.config.v2.config import Config
else:
    from cloudmesh.config.config import Config


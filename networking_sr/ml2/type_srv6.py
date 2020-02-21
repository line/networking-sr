#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutron_lib import exceptions as exc
from neutron_lib.plugins.ml2 import api
from oslo_log import log

from neutron._i18n import _

LOG = log.getLogger(__name__)
SRV6 = "srv6"


class Srv6TypeDriver(api.ML2TypeDriver):
    """Manage state for srv6 networks with ML2.

    The Srv6TypeDriver implements the 'srv6' network_type.
    """

    def __init__(self):
        super(Srv6TypeDriver, self).__init__()

    def get_type(self):
        return SRV6

    def initialize(self):
        LOG.info("ML2 Srv6TypeDriver initialization complete")

    def is_partial_segment(self, segment):
        return False

    def validate_provider_segment(self, segment):
        for key, value in segment.items():
            if value and key not in [api.NETWORK_TYPE]:
                msg = _("%s prohibited for srv6 provider network") % key
                raise exc.InvalidInput(error_message=msg)

    def reserve_provider_segment(self, context, segment, filters=None):
        return segment

    def allocate_tenant_segment(self, context, filters=None):
        return

    def release_segment(self, context, segment):
        pass

    def get_mtu(self, physical_network=None):
        pass

    def initialize_network_segment_range_support(self):
        pass

    def update_network_segment_range_allocations(self):
        pass

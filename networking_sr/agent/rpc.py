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

from neutron_lib.agent import topics
from neutron_lib import rpc as n_rpc
from oslo_log import log as logging
import oslo_messaging


LOG = logging.getLogger(__name__)

TOPICS_ENCAP = "encap"
TOPICS_ENCAP_RULE = "encap_rule"
TOPICS_VRF = "vrf"

# TODO(hichihara): This RPC API will be replaced object RPC API


class SrAgentApi(object):
    '''SR agent RPC API

    API version history:
        1.0 - Initial version.
        1.1 - Add encap rule update method
    '''

    def __init__(self, topic):
        self.topic_encap_delete = topics.get_topic_name(topic,
                                                        TOPICS_ENCAP,
                                                        topics.DELETE)
        self.topic_encap_update = topics.get_topic_name(topic,
                                                        TOPICS_ENCAP,
                                                        topics.UPDATE)
        self.topic_encap_rule_update = topics.get_topic_name(topic,
                                                             TOPICS_ENCAP_RULE,
                                                             topics.UPDATE)
        self.topic_vrf_delete = topics.get_topic_name(topic,
                                                      TOPICS_VRF,
                                                      topics.DELETE)
        target = oslo_messaging.Target(topic=topic, version='1.1')
        self.client = n_rpc.get_client(target)

    def encap_delete(self, context, port):
        cctxt = self.client.prepare(topic=self.topic_encap_delete,
                                    fanout=True)
        cctxt.cast(context, 'encap_delete', port=port)

    def encap_update(self, context, port):
        cctxt = self.client.prepare(topic=self.topic_encap_update,
                                    fanout=True)
        cctxt.cast(context, 'encap_update', port=port)

    def encap_rule_update(self, context, encap_info):
        cctxt = self.client.prepare(topic=self.topic_encap_rule_update,
                                    fanout=True)
        cctxt.cast(context, 'encap_rule_update', encap_info=encap_info)

    def vrf_delete(self, context, vrf):
        cctxt = self.client.prepare(topic=self.topic_vrf_delete,
                                    fanout=True)
        cctxt.cast(context, 'vrf_delete', vrf=vrf)

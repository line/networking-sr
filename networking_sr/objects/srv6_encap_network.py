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

from oslo_versionedobjects import fields as obj_fields

from neutron.api.rpc.callbacks import resources
from neutron.objects import base
from neutron.objects import common_types

from networking_sr.db import srv6_encap_net_db


@base.NeutronObjectRegistry.register
class SRv6EncapNetwork(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    new_facade = True
    db_model = srv6_encap_net_db.Srv6EncapNetwork

    fields = {
        'id': common_types.UUIDField(),
        'project_id': obj_fields.StringField(),
        'network_id': obj_fields.StringField(),
        'encap_rules': obj_fields.ListOfObjectsField(
            'SRv6EncapRule', nullable=True),
    }

    synthetic_fields = ['encap_rules']


@base.NeutronObjectRegistry.register
class SRv6EncapRule(base.NeutronDbObject):
    # Version 1.0: Initial version
    VERSION = '1.0'

    new_facade = True
    db_model = srv6_encap_net_db.Srv6EncapRule

    fields = {
        'srv6_encap_network_id': common_types.UUIDField(),
        'destination': obj_fields.StringField(nullable=False),
        'nexthop': obj_fields.StringField(nullable=False),
    }

    primary_keys = ['srv6_encap_network_id', 'destination', 'nexthop']
    foreign_keys = {'SRv6EncapNetwork': {'srv6_encap_network_id': 'id'}}

resources.register_resource_class(SRv6EncapNetwork)
resources.register_resource_class(SRv6EncapRule)

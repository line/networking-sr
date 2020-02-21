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

from neutron_lib.api import extensions as api_extensions
from neutron_lib import constants
from neutron_lib.db import constants as db_const

from neutron.api import extensions
from neutron.api.v2 import resource_helper

from networking_sr import extensions as sr_extensions
from networking_sr.objects import srv6_encap_network as objects  # noqa

extensions.append_api_extensions_path(sr_extensions.__path__)

ALIAS = "srv6-encap-network"

EXTENDED_ATTRIBUTES_2_0 = {
    'srv6_encap_networks': {
        'id': {'allow_post': False,
               'allow_put': False,
               'is_visible': True,
               'validate': {'type:uuid': None},
               'primary_key': True},
        'encap_rules': {'allow_post': True,
                        'allow_put': True,
                        'default': constants.ATTR_NOT_SPECIFIED,
                        'is_visible': True,
                        'enforce_policy': True},
        'project_id': {'allow_post': True, 'allow_put': False,
                       'required_by_policy': True,
                       'validate': {
                           'type:string':
                               db_const.PROJECT_ID_FIELD_SIZE},
                       'is_filter': True, 'is_sort_key': True,
                       'is_visible': True},
        'network_id': {'allow_post': True, 'allow_put': False,
                       'validate': {'type:uuid_or_none': None},
                       'is_filter': True, 'is_sort_key': True,
                       'default': None, 'is_visible': True},
    }
}


class Srv6_encap_network(api_extensions.ExtensionDescriptor):

    @classmethod
    def get_name(cls):
        return "Srv6 encap network"

    @classmethod
    def get_alias(cls):
        return ALIAS

    @classmethod
    def get_description(cls):
        return "Adds srv6 encap rules attribute to network resource."

    @classmethod
    def get_updated(cls):
        return "2019-05-27T10:00:00-00:00"

    def get_required_extensions(self):
        return []

    @classmethod
    def get_resources(cls):
        plural_mappings = resource_helper.build_plural_mappings(
            {}, EXTENDED_ATTRIBUTES_2_0)
        return resource_helper.build_resource_info(
            plural_mappings,
            EXTENDED_ATTRIBUTES_2_0,
            ALIAS)

    def get_extended_resources(self, version):
        if version == "2.0":
            return EXTENDED_ATTRIBUTES_2_0
        else:
            return {}

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

from neutron_lib.db import api as db_api
from neutron_lib.db import model_base
from neutron_lib.db import model_query
from neutron_lib.db import utils as db_utils
from neutron_lib import exceptions as lib_exc
from oslo_db import exception as db_exc
from oslo_log import log as logging
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc

from neutron.db import models_v2


LOG = logging.getLogger(__name__)


class Srv6EncapNetwork(model_base.BASEV2, model_base.HasId,
                       model_base.HasProject):
    __tablename__ = 'srv6encapnetwork'
    network_id = sa.Column(sa.String(36),
                           sa.ForeignKey('networks.id', ondelete="CASCADE"),
                           primary_key=True,
                           nullable=False)
    network = orm.relationship(
        models_v2.Network, load_on_pending=True,
        backref=orm.backref("srv6_encap_networks", lazy='subquery',
                            cascade='delete'))


class Srv6EncapRule(model_base.BASEV2):
    __tablename__ = 'srv6encaprule'
    srv6_encap_network_id = sa.Column(
        sa.String(36),
        sa.ForeignKey('srv6encapnetwork.id', ondelete="CASCADE"),
        primary_key=True,
        nullable=False)
    destination = sa.Column(sa.String(255), nullable=False, primary_key=True)
    nexthop = sa.Column(sa.String(255), nullable=False, primary_key=True)
    srv6_encap_network = orm.relationship(
        Srv6EncapNetwork,
        backref=orm.backref("srv6_encap_rules", lazy='subquery',
                            cascade='delete'))


class DuplicateDestinationEntry(lib_exc.InvalidInput):
    message = _("Duplicate destination entry in request.")


class SRv6EncapNetworkNotFound(lib_exc.NotFound):
    message = _("SRv6 encap network %(id)s doesn't exist.")


class SRv6EncapNetworkDbMixin(object):

    def _validate_srv6_encap_rules(self, encap_rules):
        dests = [rule['destination'] for rule in encap_rules]
        if len(dests) != len(set(dests)):
            raise DuplicateDestinationEntry

    def _make_srv6_encap_network_dict(self, encap_net, encap_rules,
                                      fields=None):
        rules = []
        for rule in encap_rules:
            rules.append({'destination': rule['destination'],
                          'nexthop': rule['nexthop']})
        res = {
            'id': encap_net['id'],
            'project_id': encap_net['project_id'],
            'network_id': encap_net['network_id'],
            'encap_rules': rules}
        return db_utils.resource_fields(res, fields)

    def _get_srv6_encap_network(self, context, encap_net_id):
        try:
            return model_query.get_by_id(context, Srv6EncapNetwork,
                                         encap_net_id)
        except exc.NoResultFound:
            raise SRv6EncapNetworkNotFound(id=encap_net_id)

    def _get_srv6_encap_rule(self, context, encap_net_id):
        try:
            query = model_query.query_with_hooks(context, Srv6EncapRule)
            return query.filter(
                Srv6EncapRule.srv6_encap_network_id == encap_net_id).all()
        except exc.NoResultFound:
            # TODO(hichihara)
            pass

    def get_srv6_encap_networks(self, context, filters=None,
                                fields=None, sorts=None, limit=None,
                                marker=None, page_reverse=False):
        marker_obj = self.db_utils.get_marker_obj(self, context,
                                                  'srv6_encap_networks',
                                                  limit, marker)
        encap_networks = model_query.get_collection_query(
            context, Srv6EncapNetwork,
            filters=filters, sorts=sorts,
            limit=limit, marker_obj=marker_obj,
            page_reverse=page_reverse)
        results = []
        for encap_network in encap_networks:
            encap_rule_db = self._get_srv6_encap_rule(context,
                                                      encap_network['id'])
            result = self._make_srv6_encap_network_dict(encap_network,
                                                        encap_rule_db,
                                                        fields=fields)
            results.append(result)
        return results

    def get_srv6_encap_network(self, context, encap_net_id, fields=None):
        encap_network_db = self._get_srv6_encap_network(context, encap_net_id)
        encap_rule_db = self._get_srv6_encap_rule(context, encap_net_id)
        return self._make_srv6_encap_network_dict(encap_network_db,
                                                  encap_rule_db, fields)

    def create_srv6_encap_network(self, context, srv6_encap_network):
        encap_net = srv6_encap_network['srv6_encap_network']
        self._validate_srv6_encap_rules(encap_net['encap_rules'])
        try:
            with db_api.CONTEXT_WRITER.using(context):
                encap_network_db = Srv6EncapNetwork(
                    network_id=encap_net['network_id'],
                    project_id=encap_net['project_id'],
                )
                context.session.add(encap_network_db)
        except db_exc.DBDuplicateEntry:
            # TODO(hichihara)
            pass

        try:
            with db_api.CONTEXT_WRITER.using(context):
                for rule in encap_net['encap_rules']:
                    encap_rule_db = Srv6EncapRule(
                        srv6_encap_network_id=encap_network_db.id,
                        destination=rule['destination'],
                        nexthop=rule['nexthop']
                    )
                    context.session.add(encap_rule_db)
        except db_exc.DBDuplicateEntry:
            # TODO(hichihara)
            pass

        return self._make_srv6_encap_network_dict(encap_network_db,
                                                  encap_net['encap_rules'])

    def update_srv6_encap_network(self, context, encap_net_id,
                                  srv6_encap_network):
        encap_net = srv6_encap_network['srv6_encap_network']
        self._validate_srv6_encap_rules(encap_net['encap_rules'])
        with db_api.CONTEXT_WRITER.using(context):
            encap_network_db = self._get_srv6_encap_network(context,
                                                            encap_net_id)
            encap_rules = self._get_srv6_encap_rule(context, encap_net_id)
            for rule in encap_rules:
                context.session.delete(rule)
            for rule in encap_net['encap_rules']:
                encap_rule_db = Srv6EncapRule(
                    srv6_encap_network_id=encap_net_id,
                    destination=rule['destination'],
                    nexthop=rule['nexthop']
                )
                context.session.add(encap_rule_db)
        return self._make_srv6_encap_network_dict(encap_network_db,
                                                  encap_net['encap_rules'])

    def delete_srv6_encap_network(self, context, encap_net_id):
        with db_api.CONTEXT_WRITER.using(context):
            encap_network_db = self._get_srv6_encap_network(context,
                                                            encap_net_id)
            context.session.delete(encap_network_db)

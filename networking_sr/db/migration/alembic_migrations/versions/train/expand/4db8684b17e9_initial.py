# Copyright 2019 OpenStack Foundation
#
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
#

from alembic import op
import sqlalchemy as sa


"""Start networking-sr chain

Revision ID: 4db8684b17e9
Revises: None
Create Date: 2019-05-27 05:05:36.644735

"""

# revision identifiers, used by Alembic.
revision = '4db8684b17e9'
down_revision = None


def upgrade():
    op.create_table('srv6encapnetwork',
                    sa.Column('project_id',
                              sa.String(length=255),
                              nullable=True),
                    sa.Column('id',
                              sa.String(length=36),
                              nullable=False),
                    sa.Column('network_id', sa.String(36),
                              sa.ForeignKey('networks.id',
                                            ondelete="CASCADE"),
                              nullable=False),
                    sa.PrimaryKeyConstraint('id'))

    op.create_table('srv6encaprule',
                    sa.Column('srv6_encap_network_id', sa.String(36),
                              sa.ForeignKey('srv6encapnetwork.id',
                                            ondelete="CASCADE"),
                              nullable=False),
                    sa.Column('destination', sa.String(length=255),
                              nullable=False),
                    sa.Column('nexthop', sa.String(length=255),
                              nullable=False),
                    sa.PrimaryKeyConstraint('srv6_encap_network_id',
                                            'destination',
                                            'nexthop'))

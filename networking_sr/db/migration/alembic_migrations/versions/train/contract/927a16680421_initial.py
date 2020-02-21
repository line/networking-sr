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

from neutron.db.migration import cli

"""initial contract

Revision ID: 927a16680421
Revises: None
Create Date: 2019-05-27 07:33:22.328335

"""

# revision identifiers, used by Alembic.
revision = '927a16680421'
down_revision = None
branch_labels = (cli.CONTRACT_BRANCH,)


def upgrade():
    pass

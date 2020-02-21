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

# Save trace setting
_XTRACE_NEUTRON_SR=$(set +o | grep xtrace)
set +o xtrace

dir=${GITDIR['networking-sr']}

source $dir/devstack/settings
source $dir/devstack/sr_agent

if [[ "$1" == "stack" && "$2" == "pre-install" ]]; then
    # n-api-metadata uses port 80
    sudo sed -i 's/Listen 80/Listen 8000/' /etc/httpd/conf/httpd.conf
    # Give a capability to use port 80
    if [ "$NOVA_USE_MOD_WSGI" == "False" ]; then
        sudo setcap 'cap_net_bind_service=+ep' "$NOVA_BIN_DIR/nova-api-metadata"
    else
        sudo setcap 'cap_net_bind_service=+ep' "$NOVA_BIN_DIR/uwsgi"
    fi
fi

# Restore xtrace
$_XTRACE_NEUTRON_SR

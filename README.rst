===============================
networking-sr
===============================

Networking Segment Routing is neutron plugin to manage segment routing in openstack.

The networking-sr provides SRv6(Segment Routing for IPv6) networks as neutron network resources. This project can integrate with OpenStack Neutron using ML2 mechanism of Neutron. Users can create VMs with own segment network(Tenant network) isolated from other segment networks. The VMs can access to other VMs with same segment network but they cannot access to other VMs with other segment network only. This achieves Multi-tenancy network for users and projects.

-------------------------------
Features
-------------------------------
The networking-sr project includes the following features.

* ML2 mechanism driver, type driver, and ML2 agent
* Service plugin for extension API to add SRv6 encap rule

The networking-sr project currently doesn't have the following feature.

* Gateway agent for network node

Note: This project is PoC beucase we removed and changed many codes from our production code to support latest OpenStack version. And also we have some patches to Nova and Neutron for known issues of networking-sr but they are not included in this repository.

-------------------------------
Knwon issues
-------------------------------
* Use Kernel 5.XX and not support Kernel 4.XX
* DHCP address isn't relased because DHCP release packet isn't sent

-------------------------------
Performance points
-------------------------------
* NIC offload issues
* SRH overheads
* VRF lookup
* linuxbridge between tap and VRF
* iptables for security group

-------------------------------
TODO
-------------------------------
* Add gateway agent

-------------------------------
Documetation
-------------------------------
* https://speakerdeck.com/line_developers/line-data-center-networking-with-srv6

-------------------------------
License
-------------------------------

::

    Copyright 2020 LINE Corporation
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
       http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

See `LICENSE <https://github.com/line/networking-sr/blob/master/LICENSE>`_ for more details.

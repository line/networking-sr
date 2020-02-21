Prerequisites
-------------

Before you install and configure the Networking Segment Routing service,
you must create a database, service credentials, and API endpoints.

#. To create the database, complete these steps:

   * Use the database access client to connect to the database
     server as the ``root`` user:

     .. code-block:: console

        $ mysql -u root -p

   * Create the ``networking_sr`` database:

     .. code-block:: none

        CREATE DATABASE networking_sr;

   * Grant proper access to the ``networking_sr`` database:

     .. code-block:: none

        GRANT ALL PRIVILEGES ON networking_sr.* TO 'networking_sr'@'localhost' \
          IDENTIFIED BY 'NETWORKING_SR_DBPASS';
        GRANT ALL PRIVILEGES ON networking_sr.* TO 'networking_sr'@'%' \
          IDENTIFIED BY 'NETWORKING_SR_DBPASS';

     Replace ``NETWORKING_SR_DBPASS`` with a suitable password.

   * Exit the database access client.

     .. code-block:: none

        exit;

#. Source the ``admin`` credentials to gain access to
   admin-only CLI commands:

   .. code-block:: console

      $ . admin-openrc

#. To create the service credentials, complete these steps:

   * Create the ``networking_sr`` user:

     .. code-block:: console

        $ openstack user create --domain default --password-prompt networking_sr

   * Add the ``admin`` role to the ``networking_sr`` user:

     .. code-block:: console

        $ openstack role add --project service --user networking_sr admin

   * Create the networking_sr service entities:

     .. code-block:: console

        $ openstack service create --name networking_sr --description "Networking Segment Routing" networking segment routing

#. Create the Networking Segment Routing service API endpoints:

   .. code-block:: console

      $ openstack endpoint create --region RegionOne \
        networking segment routing public http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        networking segment routing internal http://controller:XXXX/vY/%\(tenant_id\)s
      $ openstack endpoint create --region RegionOne \
        networking segment routing admin http://controller:XXXX/vY/%\(tenant_id\)s

2. Edit the ``/etc/networking_sr/networking_sr.conf`` file and complete the following
   actions:

   * In the ``[database]`` section, configure database access:

     .. code-block:: ini

        [database]
        ...
        connection = mysql+pymysql://networking_sr:NETWORKING_SR_DBPASS@controller/networking_sr

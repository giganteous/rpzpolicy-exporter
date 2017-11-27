rpzpolicy-exporter
==================

This is a server that listens on port 4242 for one or more
PowerDNS `DNS protobuf streams`_, collect RPZ statistics
about the incoming stream and logs all queries that had a hit on 
any of the configured RPZ's.

.. _DNS protobuf streams: https://docs.powerdns.com/recursor/lua-config/protobuf.html

Point your `pdns_recursor` to it with this recursor.conf setting:

.. code-block:: conf

  lua-config-file=/etc/powerdns/recursor.lua

And with this lua configuration in recursor.lua:

.. code-block:: lua

    protobufServer("127.0.0.1:4242" , 2, 100, 1)
    rpzMaster("1.2.3.4", "drop.rpz.something", {refresh=30, policyName="drop", defpol=Policy.NODATA})
    rpzMaster("1.2.3.4", "dbl.rpz.something", {refresh=30, policyName="dbl", defpol=Policy.NODATA})

This config enables:

* A protobuf stream that points to rpzpolicy-exporter running on port 4242
* An RPZ config that returns NODATA on answers that contain IP's from a DROP list
* An RPZ config that returns NODATA on queries to blacklisted domains

Metrics that this daemon provides:

.. code-block::

    pdns_protobuf_rpz_applied_policy_total{policy="clean",resolver="192.168.1.1"} 359131
    pdns_protobuf_rpz_applied_policy_total{policy="dbl",resolver="192.168.1.1"} 420
    pdns_protobuf_rpz_applied_policy_total{policy="drop",resolver="192.168.1.1"} 4

The total queries is `pdns_protobuf_rpz_applied_policy_total`, you can sum these by resolver and/or policy.

The following prometheus query you can use in a grafana dashboard to plot the applied policies against the total:

.. code-block:: prometheus

    sum(rate(pdns_protobuf_rpz_applied_policy_total{policy!="clean"}[1m])) by (policy, resolver) / ignoring(policy) group_left sum(rate(pdns_protobuf_rpz_applied_policy_total[1m])) by ( resolver) * 100


#!/bin/sh
# Runs inside the Kubo container before the daemon starts (/container-init.d/).
# The stack's IPFS node is a local content store: no public DHT, so `add` never blocks on
# providing records to the network (observed: adds hanging for minutes on a fresh node) and the
# demo works without internet (Manual §16). A production deployment would pin to a cluster.
set -e
ipfs config Routing.Type none
ipfs config --json Swarm.DisableNatPortMap true
ipfs config --json Bootstrap '[]'
